/* Diagnostic VFS only: forwards normal I/O and can deny SHM before delegation.
 * No SQLite library is linked; all APIs come from the loading connection.
 * This is NOT the production checked-filesystem implementation.
 */
#include "sqlite3.h"
#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1
#include <string.h>

#define PROBE_NAME "mordred_probe_v1"
typedef struct ProbeFile {
  sqlite3_file base;
  sqlite3_file *real;
} ProbeFile;
static sqlite3_vfs wrapper;
static sqlite3_vfs *parent;
static sqlite3_int64 opens, deletes, maps, unmaps, denied, delegated;
static int deny_shm;

static ProbeFile *pf(sqlite3_file *f) { return (ProbeFile *)f; }
static int pClose(sqlite3_file *f) {
  int rc = pf(f)->real->pMethods->xClose(pf(f)->real);
  f->pMethods = 0;
  return rc;
}
static int pRead(sqlite3_file *f, void *b, int n, sqlite3_int64 o) {
  return pf(f)->real->pMethods->xRead(pf(f)->real,b,n,o);
}
static int pWrite(sqlite3_file *f, const void *b, int n, sqlite3_int64 o) {
  return pf(f)->real->pMethods->xWrite(pf(f)->real,b,n,o);
}
static int pTruncate(sqlite3_file *f, sqlite3_int64 n) {
  return pf(f)->real->pMethods->xTruncate(pf(f)->real,n);
}
static int pSync(sqlite3_file *f, int flags) { return pf(f)->real->pMethods->xSync(pf(f)->real,flags); }
static int pSize(sqlite3_file *f, sqlite3_int64 *n) { return pf(f)->real->pMethods->xFileSize(pf(f)->real,n); }
static int pLock(sqlite3_file *f, int n) { return pf(f)->real->pMethods->xLock(pf(f)->real,n); }
static int pUnlock(sqlite3_file *f, int n) { return pf(f)->real->pMethods->xUnlock(pf(f)->real,n); }
static int pReserved(sqlite3_file *f, int *n) { return pf(f)->real->pMethods->xCheckReservedLock(pf(f)->real,n); }
static int pControl(sqlite3_file *f, int op, void *arg) {
  int rc = pf(f)->real->pMethods->xFileControl(pf(f)->real,op,arg);
  if (op == SQLITE_FCNTL_VFSNAME && rc == SQLITE_OK) {
    char **name = (char **)arg;
    *name = sqlite3_mprintf(PROBE_NAME "/%z", *name);
    if (!*name) return SQLITE_NOMEM;
  }
  return rc;
}
static int pSector(sqlite3_file *f) { return pf(f)->real->pMethods->xSectorSize(pf(f)->real); }
static int pCharacteristics(sqlite3_file *f) { return pf(f)->real->pMethods->xDeviceCharacteristics(pf(f)->real); }
static int pMap(sqlite3_file *f, int page, int size, int extend, void volatile **out) {
  maps++;
  if (deny_shm) { denied++; *out = 0; return SQLITE_IOERR_SHMMAP; }
  delegated++;
  if (!pf(f)->real->pMethods->xShmMap) return SQLITE_IOERR_SHMMAP;
  return pf(f)->real->pMethods->xShmMap(pf(f)->real,page,size,extend,out);
}
static int pShmLock(sqlite3_file *f, int offset, int n, int flags) {
  return pf(f)->real->pMethods->xShmLock(pf(f)->real,offset,n,flags);
}
static void pBarrier(sqlite3_file *f) { pf(f)->real->pMethods->xShmBarrier(pf(f)->real); }
static int pUnmap(sqlite3_file *f, int remove) {
  unmaps++;
  return pf(f)->real->pMethods->xShmUnmap(pf(f)->real,remove);
}
static int pFetch(sqlite3_file *f, sqlite3_int64 offset, int n, void **out) {
  if (!pf(f)->real->pMethods->xFetch) { *out = 0; return SQLITE_OK; }
  return pf(f)->real->pMethods->xFetch(pf(f)->real,offset,n,out);
}
static int pUnfetch(sqlite3_file *f, sqlite3_int64 offset, void *out) {
  if (!pf(f)->real->pMethods->xUnfetch) return SQLITE_OK;
  return pf(f)->real->pMethods->xUnfetch(pf(f)->real,offset,out);
}
static const sqlite3_io_methods methods1 = {
  1,pClose,pRead,pWrite,pTruncate,pSync,pSize,pLock,pUnlock,pReserved,pControl,pSector,pCharacteristics,
  0,0,0,0,0,0
};
static const sqlite3_io_methods methods2 = {
  2,pClose,pRead,pWrite,pTruncate,pSync,pSize,pLock,pUnlock,pReserved,pControl,pSector,pCharacteristics,
  pMap,pShmLock,pBarrier,pUnmap,0,0
};
static const sqlite3_io_methods methods3 = {
  3,pClose,pRead,pWrite,pTruncate,pSync,pSize,pLock,pUnlock,pReserved,pControl,pSector,pCharacteristics,
  pMap,pShmLock,pBarrier,pUnmap,pFetch,pUnfetch
};
static int vOpen(sqlite3_vfs *v, const char *name, sqlite3_file *f, int flags, int *out) {
  ProbeFile *p = (ProbeFile *)f;
  int rc;
  (void)v;
  memset(p,0,sizeof(*p)+(size_t)parent->szOsFile);
  p->real = (sqlite3_file *)(p+1);
  opens++;
  rc = parent->xOpen(parent,name,p->real,flags,out);
  if (p->real->pMethods) {
    int version = p->real->pMethods->iVersion;
    f->pMethods = version >= 3 ? &methods3 : version == 2 ? &methods2 : &methods1;
  }
  return rc;
}
static int vDelete(sqlite3_vfs *v, const char *name, int sync) {
  (void)v; deletes++; return parent->xDelete(parent,name,sync);
}
static int vAccess(sqlite3_vfs *v,const char *name,int flags,int *out) {
  (void)v; return parent->xAccess(parent,name,flags,out);
}
static int vFull(sqlite3_vfs *v,const char *name,int n,char *out) {
  (void)v; return parent->xFullPathname(parent,name,n,out);
}
static void *vDlOpen(sqlite3_vfs *v,const char *name) { (void)v; return parent->xDlOpen(parent,name); }
static void vDlError(sqlite3_vfs *v,int n,char *out) { (void)v; parent->xDlError(parent,n,out); }
static void (*vDlSym(sqlite3_vfs *v,void *h,const char *name))(void) {
  (void)v; return parent->xDlSym(parent,h,name);
}
static void vDlClose(sqlite3_vfs *v,void *h) { (void)v; parent->xDlClose(parent,h); }
static int vRandom(sqlite3_vfs *v,int n,char *out) { (void)v; return parent->xRandomness(parent,n,out); }
static int vSleep(sqlite3_vfs *v,int n) { (void)v; return parent->xSleep(parent,n); }
static int vTime(sqlite3_vfs *v,double *out) { (void)v; return parent->xCurrentTime(parent,out); }
static int vError(sqlite3_vfs *v,int n,char *out) {
  (void)v; return parent->xGetLastError ? parent->xGetLastError(parent,n,out) : 0;
}
static int vTime64(sqlite3_vfs *v,sqlite3_int64 *out) {
  (void)v; return parent->xCurrentTimeInt64(parent,out);
}
static int vSet(sqlite3_vfs *v,const char *name,sqlite3_syscall_ptr p) {
  (void)v; return parent->xSetSystemCall ? parent->xSetSystemCall(parent,name,p) : SQLITE_NOTFOUND;
}
static sqlite3_syscall_ptr vGet(sqlite3_vfs *v,const char *name) {
  (void)v; return parent->xGetSystemCall ? parent->xGetSystemCall(parent,name) : 0;
}
static const char *vNext(sqlite3_vfs *v,const char *name) {
  (void)v; return parent->xNextSystemCall ? parent->xNextSystemCall(parent,name) : 0;
}
static void stats(sqlite3_context *ctx,int argc,sqlite3_value **argv) {
  char *text;
  (void)argc; (void)argv;
  text = sqlite3_mprintf(
    "{\"xOpen\":%lld,\"xDelete\":%lld,\"xShmMap\":%lld,\"xShmUnmap\":%lld,"
    "\"shmDenied\":%lld,\"shmDelegations\":%lld,\"source_id\":\"%s\",\"header_version\":\"%s\"}",
    opens,deletes,maps,unmaps,denied,delegated,sqlite3_sourceid(),SQLITE_VERSION);
  if (!text) sqlite3_result_error_nomem(ctx);
  else sqlite3_result_text(ctx,text,-1,sqlite3_free);
}
static void setDeny(sqlite3_context *ctx,int argc,sqlite3_value **argv) {
  (void)argc; deny_shm = sqlite3_value_int(argv[0]) != 0; sqlite3_result_int(ctx,deny_shm);
}
static void selected(sqlite3_context *ctx,int argc,sqlite3_value **argv) {
  char *name = 0;
  int rc;
  (void)argc; (void)argv;
  rc = sqlite3_file_control(sqlite3_context_db_handle(ctx),"main",SQLITE_FCNTL_VFSNAME,&name);
  if (rc != SQLITE_OK || !name) sqlite3_result_error(ctx,"VFS name unavailable",-1);
  else sqlite3_result_text(ctx,name,-1,sqlite3_free);
}
static int functions(sqlite3 *db,char **error,const sqlite3_api_routines *api) {
  int rc;
  (void)error; (void)api;
  rc = sqlite3_create_function(db,"mordred_probe_stats",0,SQLITE_UTF8,0,stats,0,0);
  if (rc != SQLITE_OK) return rc;
  rc = sqlite3_create_function(db,"mordred_probe_deny_shm",1,SQLITE_UTF8,0,setDeny,0,0);
  if (rc != SQLITE_OK) {
    sqlite3_create_function(db,"mordred_probe_stats",0,SQLITE_UTF8,0,0,0,0);
    return rc;
  }
  rc = sqlite3_create_function(db,"mordred_probe_vfs",0,SQLITE_UTF8,0,selected,0,0);
  if (rc != SQLITE_OK) {
    sqlite3_create_function(db,"mordred_probe_stats",0,SQLITE_UTF8,0,0,0,0);
    sqlite3_create_function(db,"mordred_probe_deny_shm",1,SQLITE_UTF8,0,0,0,0);
  }
  return rc;
}
static int preflight(sqlite3 *db) {
  sqlite3_stmt *statement = 0;
  int rc = sqlite3_prepare_v2(db,
    "SELECT 1 FROM pragma_function_list WHERE name IN "
    "('mordred_probe_stats','mordred_probe_deny_shm','mordred_probe_vfs') LIMIT 1",
    -1,&statement,0);
  if (rc != SQLITE_OK) return rc;
  rc = sqlite3_step(statement);
  sqlite3_finalize(statement);
  return rc == SQLITE_DONE ? SQLITE_OK : rc == SQLITE_ROW ? SQLITE_BUSY : rc;
}

#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_mordredprobe_init(sqlite3 *db,char **error,const sqlite3_api_routines *api) {
  int rc;
  if (sqlite3_api && sqlite3_api != api) return SQLITE_MISUSE;
  SQLITE_EXTENSION_INIT2(api);
  (void)error;
  if (parent) return SQLITE_OK_LOAD_PERMANENTLY;
  /* Until success the loader may unload this library: publish transactionally. */
  rc = preflight(db);
  if (rc != SQLITE_OK) { sqlite3_api = 0; return rc; }
  if (!parent) {
    if (sqlite3_vfs_find(PROBE_NAME)) { rc = SQLITE_ERROR; goto failed; }
    parent = sqlite3_vfs_find(0);
    if (!parent) { rc = SQLITE_ERROR; goto failed; }
    wrapper = *parent;
    wrapper.zName = PROBE_NAME;
    wrapper.szOsFile = (int)sizeof(ProbeFile)+parent->szOsFile;
    wrapper.pNext = 0;
    wrapper.xOpen=vOpen; wrapper.xDelete=vDelete; wrapper.xAccess=vAccess; wrapper.xFullPathname=vFull;
    wrapper.xDlOpen=vDlOpen; wrapper.xDlError=vDlError; wrapper.xDlSym=vDlSym; wrapper.xDlClose=vDlClose;
    wrapper.xRandomness=vRandom; wrapper.xSleep=vSleep; wrapper.xCurrentTime=vTime; wrapper.xGetLastError=vError;
    if (parent->iVersion >= 2) wrapper.xCurrentTimeInt64=vTime64;
    if (parent->iVersion >= 3) { wrapper.xSetSystemCall=vSet; wrapper.xGetSystemCall=vGet; wrapper.xNextSystemCall=vNext; }
    rc = sqlite3_vfs_register(&wrapper,0);
    if (rc != SQLITE_OK) goto failed;
    /* Functions are installed only on FUTURE connections, after this library
     * is pinned. SQLite cannot reliably undo new SQL functions from inside an
     * active load_extension() statement if later initialization fails. */
    rc = sqlite3_auto_extension((void (*)(void))functions);
    if (rc != SQLITE_OK) {
      sqlite3_cancel_auto_extension((void (*)(void))functions);
      sqlite3_vfs_unregister(&wrapper);
      goto failed;
    }
  }
  return SQLITE_OK_LOAD_PERMANENTLY;
failed:
  parent = 0;
  memset(&wrapper,0,sizeof(wrapper));
  sqlite3_api = 0;
  return rc;
}
