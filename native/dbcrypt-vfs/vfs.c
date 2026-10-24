/* Checked SQLCipher VFS, deliberately unavailable to production activation.
 * Linked only to Win32. SQLite calls use the loading driver's API table.
 * No default-VFS file, SHM, dlopen or system-call callback is delegated.
 */
#include "checked_io.h"
#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1
#include <string.h>
#include <wchar.h>
#include <limits.h>

#define VFS_NAME "mordred_checked_v1"
/* SQLite 3.51.1 src/os.h and src/os_win.c. Must remain compatible with win32
 * byte locks: databases must never be concurrently accessed with no locks. */
#define PENDING_BYTE ((DWORD)0x40000000)
#define RESERVED_BYTE (PENDING_BYTE+1)
#define SHARED_FIRST (PENDING_BYTE+2)
#define SHARED_SIZE ((DWORD)510)
#define SHM_BASE ((DWORD)((22+SQLITE_SHM_NLOCK)*4))
#define SHM_DMS (SHM_BASE+SQLITE_SHM_NLOCK)

typedef struct Region {
  HANDLE mapping;
  void *base;
  void *data;
} Region;

typedef struct CheckedFile {
  sqlite3_file base;
  CiFile io;
  CiFile shm;
  wchar_t path[CI_PATH];
  Region *regions;
  int region_count;
  int region_size;
  int lock;
  int shared;
  int reserved;
  int pending;
  unsigned int shm_shared;
  unsigned int shm_exclusive;
  int shm_deadman;
  int flags;
} CheckedFile;

static SRWLOCK registry_lock=SRWLOCK_INIT;
static sqlite3_vfs checked_vfs;
static sqlite3_vfs *services;
static CiRoot *roots;
static uint64_t next_token;
static int initialized;

static CheckedFile *cf(sqlite3_file *file) { return (CheckedFile *)file; }
static CiRoot *find_root(const wchar_t *path) {
  CiRoot *r;
  for (r=roots; r; r=r->next) if (ci_contains(r,path)) return r;
  return NULL;
}
static CiRoot *find_token(uint64_t token) {
  CiRoot *r;
  for (r=roots; r; r=r->next) if (r->token==token) return r;
  return NULL;
}

static int vDelete(sqlite3_vfs *, const char *, int);
static int fUnmap(sqlite3_file *, int);
static int fUnlock(sqlite3_file *, int);

static int fClose(sqlite3_file *file) {
  CheckedFile *f=cf(file);
  CiRoot *root=f->io.root;
  int rc=fUnmap(file,0), other;
  other=fUnlock(file,SQLITE_LOCK_NONE);
  if (rc==SQLITE_OK) rc=other;
  other=ci_close(&f->io);
  if (rc==SQLITE_OK) rc=other;
  file->pMethods=NULL;
  AcquireSRWLockExclusive(&registry_lock);
  root->files--;
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}
static int fRead(sqlite3_file *f, void *buffer, int size, sqlite3_int64 offset) {
  return ci_read(&cf(f)->io,buffer,size,offset);
}
static int fWrite(sqlite3_file *f, const void *buffer, int size, sqlite3_int64 offset) {
  return ci_write(&cf(f)->io,buffer,size,offset);
}
static int fTruncate(sqlite3_file *f, sqlite3_int64 size) { return ci_truncate(&cf(f)->io,size); }
static int fSync(sqlite3_file *f, int flags) { (void)flags; return ci_sync(&cf(f)->io); }
static int fSize(sqlite3_file *f, sqlite3_int64 *size) { return ci_size(&cf(f)->io,size); }

static int fLock(sqlite3_file *file, int requested) {
  CheckedFile *f=cf(file);
  int rc, release;
  if (ci_check(&f->io)!=SQLITE_OK) return SQLITE_IOERR_LOCK;
  if (requested<=f->lock) return SQLITE_OK;
  if (requested!=SQLITE_LOCK_SHARED && requested!=SQLITE_LOCK_RESERVED && requested!=SQLITE_LOCK_EXCLUSIVE)
    return SQLITE_IOERR_LOCK;
  if (f->io.readonly && requested>SQLITE_LOCK_SHARED) return SQLITE_READONLY;
  if (f->lock==SQLITE_LOCK_NONE) {
    if (requested!=SQLITE_LOCK_SHARED) return SQLITE_IOERR_LOCK;
    rc=ci_lock(&f->io,PENDING_BYTE,1,0);
    if (rc!=SQLITE_OK) return rc;
    rc=ci_lock(&f->io,SHARED_FIRST,SHARED_SIZE,0);
    release=ci_unlock(&f->io,PENDING_BYTE,1);
    if (rc==SQLITE_OK) { f->shared=1; f->lock=SQLITE_LOCK_SHARED; }
    return release==SQLITE_OK ? rc : release;
  }
  if (requested==SQLITE_LOCK_RESERVED) {
    rc=ci_lock(&f->io,RESERVED_BYTE,1,1);
    if (rc==SQLITE_OK) { f->reserved=1; f->lock=SQLITE_LOCK_RESERVED; }
    return rc;
  }
  if (!f->pending) {
    rc=ci_lock(&f->io,PENDING_BYTE,1,1);
    if (rc!=SQLITE_OK) return rc;
    f->pending=1; f->lock=SQLITE_LOCK_PENDING;
  }
  if (f->shared) {
    rc=ci_unlock(&f->io,SHARED_FIRST,SHARED_SIZE);
    if (rc!=SQLITE_OK) return rc;
    f->shared=0;
  }
  rc=ci_lock(&f->io,SHARED_FIRST,SHARED_SIZE,1);
  if (rc==SQLITE_OK) f->lock=SQLITE_LOCK_EXCLUSIVE;
  else {
    /* Retain PENDING to stop new readers; restore our read lock on failure. */
    release=ci_lock(&f->io,SHARED_FIRST,SHARED_SIZE,0);
    if (release!=SQLITE_OK) return SQLITE_IOERR_LOCK;
    f->shared=1;
  }
  return rc;
}

static int fUnlock(sqlite3_file *file, int requested) {
  CheckedFile *f=cf(file);
  int rc=SQLITE_OK, other;
  if (requested!=SQLITE_LOCK_NONE && requested!=SQLITE_LOCK_SHARED) return SQLITE_IOERR_UNLOCK;
  if (f->lock<=requested) return SQLITE_OK;
  if (f->lock==SQLITE_LOCK_EXCLUSIVE) {
    rc=ci_unlock(&f->io,SHARED_FIRST,SHARED_SIZE);
    if (rc!=SQLITE_OK) return rc;
    if (requested==SQLITE_LOCK_SHARED) {
      rc=ci_lock(&f->io,SHARED_FIRST,SHARED_SIZE,0);
      if (rc==SQLITE_OK) f->shared=1;
    }
  }
  if (f->shared && requested==SQLITE_LOCK_NONE) {
    other=ci_unlock(&f->io,SHARED_FIRST,SHARED_SIZE);
    if (rc==SQLITE_OK) rc=other;
    f->shared=0;
  }
  if (f->reserved) {
    other=ci_unlock(&f->io,RESERVED_BYTE,1);
    if (rc==SQLITE_OK) rc=other;
    f->reserved=0;
  }
  if (f->pending) {
    other=ci_unlock(&f->io,PENDING_BYTE,1);
    if (rc==SQLITE_OK) rc=other;
    f->pending=0;
  }
  f->lock=requested;
  return rc;
}

static int fReserved(sqlite3_file *file, int *out) {
  CheckedFile *f=cf(file);
  int rc;
  *out=0;
  if (ci_check(&f->io)!=SQLITE_OK) return SQLITE_IOERR_CHECKRESERVEDLOCK;
  if (f->reserved) { *out=1; return SQLITE_OK; }
  rc=ci_lock(&f->io,RESERVED_BYTE,1,1);
  if (rc==SQLITE_BUSY) { *out=1; return SQLITE_OK; }
  if (rc!=SQLITE_OK) return SQLITE_IOERR_CHECKRESERVEDLOCK;
  return ci_unlock(&f->io,RESERVED_BYTE,1);
}

static int fControl(sqlite3_file *file, int op, void *arg) {
  CheckedFile *f=cf(file);
  if (op==SQLITE_FCNTL_VFS_POINTER) { *(sqlite3_vfs **)arg=&checked_vfs; return SQLITE_OK; }
  if (op==SQLITE_FCNTL_VFSNAME) {
    *(char **)arg=sqlite3_mprintf(VFS_NAME);
    return *(char **)arg ? SQLITE_OK : SQLITE_NOMEM;
  }
  if (op==SQLITE_FCNTL_LOCKSTATE) { *(int *)arg=f->lock; return SQLITE_OK; }
  if (op==SQLITE_FCNTL_HAS_MOVED) { *(int *)arg=ci_check(&f->io)!=SQLITE_OK; return SQLITE_OK; }
  if (op==SQLITE_FCNTL_PERSIST_WAL || op==SQLITE_FCNTL_POWERSAFE_OVERWRITE) {
    if (*(int *)arg>0) return SQLITE_ERROR;
    *(int *)arg=0; return SQLITE_OK;
  }
  if (op==SQLITE_FCNTL_MMAP_SIZE) { *(sqlite3_int64 *)arg=0; return SQLITE_OK; }
  if (op==SQLITE_FCNTL_SIZE_HINT || op==SQLITE_FCNTL_CHUNK_SIZE) return SQLITE_OK;
  return SQLITE_NOTFOUND;
}
static int fSector(sqlite3_file *file) { (void)file; return 4096; }
static int fCharacteristics(sqlite3_file *file) { (void)file; return 0; }

static int shm_open(CheckedFile *f) {
  wchar_t name[CI_PATH];
  int rc, release;
  if (f->shm.handle) return ci_check(&f->shm);
  if (!(f->flags&SQLITE_OPEN_MAIN_DB) || f->io.readonly || wcslen(f->path)+4>=CI_PATH) return SQLITE_IOERR_SHMOPEN;
  wcscpy_s(name,CI_PATH,f->path); wcscat_s(name,CI_PATH,L"-shm");
  rc=ci_open(f->io.root,name,1,0,0,&f->shm);
  if (rc!=SQLITE_OK) return SQLITE_IOERR_SHMOPEN;
  /* The deadman byte belongs to this owned handle. Exclusive means there are
   * no live users: clear a stale WAL index before admitting shared users. */
  rc=ci_lock(&f->shm,SHM_DMS,1,1);
  if (rc==SQLITE_OK) {
    rc=ci_truncate(&f->shm,0);
    release=ci_unlock(&f->shm,SHM_DMS,1);
    if (rc==SQLITE_OK) rc=release;
  } else if (rc==SQLITE_BUSY) rc=SQLITE_OK;
  if (rc==SQLITE_OK) rc=ci_lock(&f->shm,SHM_DMS,1,0);
  if (rc!=SQLITE_OK) { ci_close(&f->shm); return rc; }
  f->shm_deadman=1;
  return SQLITE_OK;
}

static int fMap(sqlite3_file *file, int page, int size, int extend, void volatile **out) {
  CheckedFile *f=cf(file);
  sqlite3_int64 length, wanted, offset, aligned;
  SYSTEM_INFO system;
  Region *regions, *region;
  SECURITY_ATTRIBUTES sa={sizeof(sa),f->io.root->creation,FALSE};
  int rc;
  *out=NULL;
  InterlockedIncrement64(&f->io.root->maps);
  if (page<0 || page>INT_MAX/32768-1 || size!=32768 || ci_check(&f->io)!=SQLITE_OK) return SQLITE_IOERR_SHMMAP;
  rc=shm_open(f);
  if (rc!=SQLITE_OK) return rc;
  if (f->region_size && f->region_size!=size) return SQLITE_IOERR_SHMMAP;
  wanted=((sqlite3_int64)page+1)*size;
  rc=ci_size(&f->shm,&length);
  if (rc!=SQLITE_OK) return SQLITE_IOERR_SHMSIZE;
  if (length<wanted && !extend) return SQLITE_OK;
  if (page>=f->region_count) {
    regions=(Region *)sqlite3_realloc64(f->regions,((sqlite3_uint64)page+1)*sizeof(Region));
    if (!regions) return SQLITE_NOMEM;
    memset(regions+f->region_count,0,((size_t)page+1-(size_t)f->region_count)*sizeof(Region));
    f->regions=regions; f->region_count=page+1; f->region_size=size;
  }
  region=&f->regions[page];
  if (!region->base) {
    if (ci_check(&f->shm)!=SQLITE_OK || ci_test_stage(CI_BEFORE_MAP,f->shm.handle)) return SQLITE_IOERR_SHMMAP;
    /* A larger unnamed mapping grows the checked file. Existing mapped views
     * stay valid; never truncate a file underneath live views to extend it. */
    region->mapping=CreateFileMappingW(f->shm.handle,&sa,PAGE_READWRITE,(DWORD)((uint64_t)wanted>>32),(DWORD)wanted,NULL);
    if (!region->mapping) return SQLITE_IOERR_SHMMAP;
    GetSystemInfo(&system);
    offset=(sqlite3_int64)page*size;
    aligned=offset-offset%system.dwAllocationGranularity;
    region->base=MapViewOfFile(region->mapping,FILE_MAP_READ|FILE_MAP_WRITE,
                              (DWORD)((uint64_t)aligned>>32),(DWORD)aligned,(SIZE_T)(offset-aligned+size));
    if (!region->base) { CloseHandle(region->mapping); region->mapping=NULL; return SQLITE_IOERR_SHMMAP; }
    region->data=(char *)region->base+(size_t)(offset-aligned);
  }
  *out=region->data;
  return SQLITE_OK;
}

static int fShmLock(sqlite3_file *file, int offset, int count, int flags) {
  CheckedFile *f=cf(file);
  unsigned int mask;
  int rc, exclusive=(flags&SQLITE_SHM_EXCLUSIVE)!=0;
  if (!f->shm.handle || offset<0 || count<1 || offset>SQLITE_SHM_NLOCK-count ||
      (flags!=(SQLITE_SHM_LOCK|SQLITE_SHM_SHARED) && flags!=(SQLITE_SHM_LOCK|SQLITE_SHM_EXCLUSIVE) &&
       flags!=(SQLITE_SHM_UNLOCK|SQLITE_SHM_SHARED) && flags!=(SQLITE_SHM_UNLOCK|SQLITE_SHM_EXCLUSIVE))) return SQLITE_IOERR_SHMLOCK;
  mask=((1U<<count)-1)<<offset;
  if (flags&SQLITE_SHM_UNLOCK) {
    unsigned int held=exclusive ? f->shm_exclusive : f->shm_shared;
    if ((held&mask)!=mask) return SQLITE_IOERR_SHMLOCK;
    rc=ci_unlock(&f->shm,SHM_BASE+(DWORD)offset,(DWORD)count);
    if (rc==SQLITE_OK) { f->shm_shared&=~mask; f->shm_exclusive&=~mask; }
    return rc;
  }
  if ((f->shm_shared|f->shm_exclusive)&mask) return SQLITE_IOERR_SHMLOCK;
  rc=ci_lock(&f->shm,SHM_BASE+(DWORD)offset,(DWORD)count,exclusive);
  if (rc==SQLITE_OK) {
    if (exclusive) f->shm_exclusive|=mask;
    else f->shm_shared|=mask;
  }
  return rc;
}

static void fBarrier(sqlite3_file *file) { (void)file; MemoryBarrier(); }

static int fUnmap(sqlite3_file *file, int remove) {
  CheckedFile *f=cf(file);
  int i, rc=SQLITE_OK;
  wchar_t name[CI_PATH];
  CiFile deletion;
  if (!f->shm.handle) return SQLITE_OK;
  InterlockedIncrement64(&f->io.root->unmaps);
  for (i=0; i<f->region_count; i++) {
    if (f->regions[i].base && !UnmapViewOfFile(f->regions[i].base)) rc=SQLITE_IOERR_SHMMAP;
    if (f->regions[i].mapping && !CloseHandle(f->regions[i].mapping)) rc=SQLITE_IOERR_CLOSE;
  }
  sqlite3_free(f->regions); f->regions=NULL; f->region_count=0; f->region_size=0;
  /* Close releases every remaining byte lock, including the deadman lock.
   * Delete requests open a checked DELETE handle with no delete-sharing; if
   * another live user has opened SHM, sharing refusal leaves it for recovery. */
  if (ci_close(&f->shm)!=SQLITE_OK) rc=SQLITE_IOERR_CLOSE;
  f->shm_deadman=0; f->shm_shared=0; f->shm_exclusive=0;
  if (remove && rc==SQLITE_OK) {
    wcscpy_s(name,CI_PATH,f->path); wcscat_s(name,CI_PATH,L"-shm");
    if (ci_open(f->io.root,name,0,0,1,&deletion)==SQLITE_OK) {
      InterlockedIncrement64(&f->io.root->deletes);
      rc=ci_delete(&deletion);
      ci_close(&deletion);
    }
  }
  return rc;
}

static const sqlite3_io_methods methods={
  2,fClose,fRead,fWrite,fTruncate,fSync,fSize,fLock,fUnlock,fReserved,fControl,fSector,fCharacteristics,
  fMap,fShmLock,fBarrier,fUnmap,NULL,NULL
};

static int uri_allowed(const char *name, int flags) {
  int i;
  const char *key, *value;
  if (!(flags&SQLITE_OPEN_URI)) return 1;
  for (i=0; (key=sqlite3_uri_key(name,i))!=NULL; i++) {
    value=sqlite3_uri_parameter(name,key);
    if (!strcmp(key,"vfs") && value && !strcmp(value,VFS_NAME)) continue;
    if (!strcmp(key,"mode") && value && (!strcmp(value,"ro") || !strcmp(value,"rw") || !strcmp(value,"rwc"))) continue;
    return 0;
  }
  return 1;
}

static int vOpen(sqlite3_vfs *vfs, const char *name, sqlite3_file *file, int flags, int *out) {
  CheckedFile *f=cf(file);
  CiRoot *root;
  int type=flags&(SQLITE_OPEN_MAIN_DB|SQLITE_OPEN_MAIN_JOURNAL|SQLITE_OPEN_TEMP_DB|SQLITE_OPEN_TEMP_JOURNAL|
                  SQLITE_OPEN_TRANSIENT_DB|SQLITE_OPEN_SUBJOURNAL|SQLITE_OPEN_SUPER_JOURNAL|SQLITE_OPEN_WAL);
  int rc=SQLITE_CANTOPEN;
  (void)vfs;
  memset(f,0,sizeof(*f));
  if (!name || (type!=SQLITE_OPEN_MAIN_DB && type!=SQLITE_OPEN_MAIN_JOURNAL && type!=SQLITE_OPEN_WAL) ||
      flags&(SQLITE_OPEN_DELETEONCLOSE|SQLITE_OPEN_MEMORY) || !uri_allowed(name,flags) ||
      ci_utf8(name,f->path)!=SQLITE_OK) return SQLITE_CANTOPEN;
  if (type==SQLITE_OPEN_MAIN_DB && wcslen(f->path)>CI_PATH-1-8) return SQLITE_CANTOPEN;
  AcquireSRWLockExclusive(&registry_lock);
  root=find_root(f->path);
  if (root) {
    InterlockedIncrement64(&root->opens);
    rc=ci_open(root,f->path,(flags&SQLITE_OPEN_CREATE)!=0,(flags&SQLITE_OPEN_READONLY)!=0,0,&f->io);
    if (rc==SQLITE_OK) {
      root->files++;
      f->flags=flags;
      file->pMethods=&methods;
      if (out) *out=flags;
    }
  }
  ReleaseSRWLockExclusive(&registry_lock);
  return rc==SQLITE_NOTFOUND ? SQLITE_CANTOPEN : rc;
}

static int vDelete(sqlite3_vfs *vfs, const char *name, int sync) {
  wchar_t path[CI_PATH];
  CiRoot *root;
  CiFile file;
  int rc=SQLITE_IOERR_DELETE;
  (void)vfs; (void)sync;
  if (ci_utf8(name,path)!=SQLITE_OK) return rc;
  AcquireSRWLockExclusive(&registry_lock);
  root=find_root(path);
  if (root) {
    InterlockedIncrement64(&root->deletes);
    rc=ci_open(root,path,0,0,1,&file);
    if (rc==SQLITE_OK) { rc=ci_delete(&file); ci_close(&file); }
    else if (rc==SQLITE_NOTFOUND) rc=SQLITE_IOERR_DELETE_NOENT;
  }
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}

static int vAccess(sqlite3_vfs *vfs, const char *name, int flags, int *out) {
  wchar_t path[CI_PATH];
  CiRoot *root;
  CiFile file;
  int rc=SQLITE_IOERR_ACCESS;
  (void)vfs;
  *out=0;
  if (ci_utf8(name,path)!=SQLITE_OK) return rc;
  AcquireSRWLockExclusive(&registry_lock);
  root=find_root(path);
  if (root) {
    rc=ci_open(root,path,0,flags!=SQLITE_ACCESS_READWRITE,0,&file);
    if (rc==SQLITE_OK) { *out=1; ci_close(&file); }
    else if (rc==SQLITE_NOTFOUND) rc=SQLITE_OK;
  }
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}

static int vFull(sqlite3_vfs *vfs, const char *name, int size, char *out) {
  wchar_t path[CI_PATH];
  CiRoot *root;
  int rc=SQLITE_CANTOPEN;
  (void)vfs;
  if (size<=0 || ci_utf8(name,path)!=SQLITE_OK || wcslen(path)>CI_PATH-1-8) return rc;
  AcquireSRWLockExclusive(&registry_lock);
  root=find_root(path);
  if (root && ci_root_check(root)==SQLITE_OK && WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,path,-1,out,size,NULL,NULL)) rc=SQLITE_OK;
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}
static void *vDlOpen(sqlite3_vfs *v, const char *name) { (void)v; (void)name; return NULL; }
static void vDlError(sqlite3_vfs *v, int size, char *out) {
  (void)v;
  if (size>0) sqlite3_snprintf(size,out,"checked VFS refuses extension loading");
}
static void (*vDlSym(sqlite3_vfs *v, void *handle, const char *name))(void) {
  (void)v; (void)handle; (void)name; return NULL;
}
static void vDlClose(sqlite3_vfs *v, void *handle) { (void)v; (void)handle; }
static int vRandom(sqlite3_vfs *v, int n, char *out) { (void)v; return services->xRandomness(services,n,out); }
static int vSleep(sqlite3_vfs *v, int n) { (void)v; return services->xSleep(services,n); }
static int vTime(sqlite3_vfs *v, double *out) { (void)v; return services->xCurrentTime(services,out); }
static int vTime64(sqlite3_vfs *v, sqlite3_int64 *out) {
  double julian;
  int rc;
  (void)v;
  if (services->iVersion>=2 && services->xCurrentTimeInt64) return services->xCurrentTimeInt64(services,out);
  rc=services->xCurrentTime(services,&julian); *out=(sqlite3_int64)(julian*86400000.0); return rc;
}
static int vError(sqlite3_vfs *v, int n, char *out) { (void)v; if (n>0) out[0]=0; return (int)GetLastError(); }

static int authorizer(void *data,int action,const char *first,const char *second,const char *db,const char *trigger) {
  (void)data; (void)db; (void)trigger;
  /* VACUUM internally ATTACHes a temporary database and is also refused until
   * a reviewed same-library SQL gateway can distinguish its internal attach. */
  if (action==SQLITE_ATTACH || action==SQLITE_DETACH) return SQLITE_DENY;
  if (action==SQLITE_FUNCTION && second && !sqlite3_stricmp(second,"load_extension")) return SQLITE_DENY;
  if (action==SQLITE_PRAGMA && first && second) {
    if (!sqlite3_stricmp(first,"temp_store") && sqlite3_stricmp(second,"memory") && strcmp(second,"2")) return SQLITE_DENY;
    if (!sqlite3_stricmp(first,"temp_store_directory") || !sqlite3_stricmp(first,"data_store_directory")) return SQLITE_DENY;
  }
  return SQLITE_OK;
}

static int connection_init(sqlite3 *db, char **error, const sqlite3_api_routines *api) {
  sqlite3_vfs *selected=NULL;
  int rc;
  (void)error;
  if (api!=sqlite3_api) return SQLITE_MISUSE;
  if (sqlite3_file_control(db,"main",SQLITE_FCNTL_VFS_POINTER,&selected)!=SQLITE_OK || selected!=&checked_vfs) return SQLITE_OK;
  rc=sqlite3_exec(db,"PRAGMA temp_store=MEMORY; PRAGMA mmap_size=0",NULL,NULL,NULL);
  if (rc!=SQLITE_OK) return rc;
  rc=sqlite3_db_config(db,SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,0,NULL);
  if (rc!=SQLITE_OK) return rc;
  return sqlite3_set_authorizer(db,authorizer,NULL);
}

__declspec(dllexport)
int sqlite3_mordredvfs_init(sqlite3 *db, char **error, const sqlite3_api_routines *api) {
  int rc=SQLITE_OK;
  (void)db; (void)error;
  AcquireSRWLockExclusive(&registry_lock);
  if (sqlite3_api && sqlite3_api!=api) { rc=SQLITE_MISUSE; goto done; }
  if (initialized) { rc=SQLITE_OK_LOAD_PERMANENTLY; goto done; }
  SQLITE_EXTENSION_INIT2(api);
  if (sqlite3_vfs_find(VFS_NAME)) { rc=SQLITE_ERROR; goto failed; }
  services=sqlite3_vfs_find(NULL);
  if (!services) { rc=SQLITE_ERROR; goto failed; }
  memset(&checked_vfs,0,sizeof(checked_vfs));
  checked_vfs.iVersion=2; checked_vfs.szOsFile=(int)sizeof(CheckedFile); checked_vfs.mxPathname=CI_PATH*4;
  checked_vfs.zName=VFS_NAME;
  checked_vfs.xOpen=vOpen; checked_vfs.xDelete=vDelete; checked_vfs.xAccess=vAccess; checked_vfs.xFullPathname=vFull;
  checked_vfs.xDlOpen=vDlOpen; checked_vfs.xDlError=vDlError; checked_vfs.xDlSym=vDlSym; checked_vfs.xDlClose=vDlClose;
  checked_vfs.xRandomness=vRandom; checked_vfs.xSleep=vSleep; checked_vfs.xCurrentTime=vTime;
  checked_vfs.xGetLastError=vError; checked_vfs.xCurrentTimeInt64=vTime64;
  rc=sqlite3_vfs_register(&checked_vfs,0);
  if (rc!=SQLITE_OK) goto failed;
  /* No callback is published on the bootstrap connection. Future protected
   * connections cannot exist until roots are registered AFTER permanent load. */
  rc=sqlite3_auto_extension((void (*)(void))connection_init);
  if (rc!=SQLITE_OK) {
    sqlite3_cancel_auto_extension((void (*)(void))connection_init);
    sqlite3_vfs_unregister(&checked_vfs);
    goto failed;
  }
  initialized=1;
  rc=SQLITE_OK_LOAD_PERMANENTLY;
  goto done;
failed:
  services=NULL; sqlite3_api=NULL; memset(&checked_vfs,0,sizeof(checked_vfs));
done:
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}

__declspec(dllexport)
int mordred_vfs_register_root(const wchar_t *path, uint64_t *token) {
  CiRoot *root, *other;
  int rc=SQLITE_MISUSE;
  if (!token) return rc;
  *token=0;
  AcquireSRWLockExclusive(&registry_lock);
  if (!initialized) goto done;
  root=(CiRoot *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(CiRoot));
  if (!root) { rc=SQLITE_NOMEM; goto done; }
  rc=ci_root_open(root,path);
  if (rc!=SQLITE_OK) { HeapFree(GetProcessHeap(),0,root); goto done; }
  for (other=roots; other; other=other->next) {
    if (!CompareStringOrdinal(root->path,-1,other->path,-1,TRUE) ||
        CompareStringOrdinal(root->path,-1,other->path,-1,TRUE)==CSTR_EQUAL ||
        ci_contains(other,root->path) || ci_contains(root,other->path)) {
      rc=SQLITE_BUSY; ci_root_close(root); HeapFree(GetProcessHeap(),0,root); goto done;
    }
  }
  root->token=++next_token;
  root->next=roots; roots=root; *token=root->token;
done:
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}

__declspec(dllexport)
int mordred_vfs_close_root(uint64_t token) {
  CiRoot **link, *root;
  int rc=SQLITE_NOTFOUND;
  AcquireSRWLockExclusive(&registry_lock);
  for (link=&roots; (root=*link)!=NULL; link=&root->next) {
    if (root->token!=token) continue;
    if (root->files) { rc=SQLITE_BUSY; break; }
    *link=root->next; ci_root_close(root); HeapFree(GetProcessHeap(),0,root); rc=SQLITE_OK; break;
  }
  ReleaseSRWLockExclusive(&registry_lock);
  return rc;
}

__declspec(dllexport)
int mordred_vfs_stats(uint64_t token, char *out, int size) {
  CiRoot *r;
  int rc=SQLITE_NOTFOUND;
  if (size<1024 || !out) return SQLITE_MISUSE;
  AcquireSRWLockShared(&registry_lock);
  r=find_token(token);
  if (r) {
    sqlite3_snprintf(size,out,
      "{\"xOpen\":%lld,\"xDelete\":%lld,\"xShmMap\":%lld,\"xShmUnmap\":%lld,"
      "\"xSync\":%lld,\"xTruncate\":%lld,\"created\":%lld,\"private_at_creation\":%lld,"
      "\"data_opens\":%lld,\"unchecked_opens\":0}",
      InterlockedCompareExchange64(&r->opens,0,0),InterlockedCompareExchange64(&r->deletes,0,0),
      InterlockedCompareExchange64(&r->maps,0,0),InterlockedCompareExchange64(&r->unmaps,0,0),
      InterlockedCompareExchange64(&r->syncs,0,0),InterlockedCompareExchange64(&r->truncates,0,0),
      InterlockedCompareExchange64(&r->created,0,0),InterlockedCompareExchange64(&r->private_created,0,0),
      InterlockedCompareExchange64(&r->data_opens,0,0));
    rc=SQLITE_OK;
  }
  ReleaseSRWLockShared(&registry_lock);
  return rc;
}

#ifdef MORDRED_VFS_TESTING
/* Invoke the actual VFS callbacks/Win32 locks for the recovery-only transition
 * that SQL's ordinary BEGIN EXCLUSIVE reaches through RESERVED instead.
 * No content is written; the caller supplies a synthetic admitted pathname. */
__declspec(dllexport)
int mordred_vfs_test_recovery_lock(const char *path, int *reserved) {
  CheckedFile *file;
  int rc, closing;
  if (!initialized || !reserved) return SQLITE_MISUSE;
  *reserved=-1;
  file=(CheckedFile *)sqlite3_malloc64(sizeof(CheckedFile));
  if (!file) return SQLITE_NOMEM;
  rc=vOpen(&checked_vfs,path,&file->base,SQLITE_OPEN_MAIN_DB|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,NULL);
  if (rc==SQLITE_OK) {
    rc=fLock(&file->base,SQLITE_LOCK_SHARED);
    if (rc==SQLITE_OK) rc=fLock(&file->base,SQLITE_LOCK_EXCLUSIVE);
    if (rc==SQLITE_OK) rc=fReserved(&file->base,reserved);
    closing=fClose(&file->base);
    if (rc==SQLITE_OK) rc=closing;
  }
  sqlite3_free(file);
  return rc;
}
#endif
