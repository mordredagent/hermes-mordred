/* Win32 owned-handle boundary. SQLite library APIs are not used here.
 * Policy mirrors _private_fs/_windows_security.py (storage, not public-build).
 * All ancestors exclude FILE_SHARE_DELETE for the lifetime of the open object.
 */
#include "checked_io.h"
#include <aclapi.h>
#include <sddl.h>
#include <wchar.h>
#include <string.h>
#include <stddef.h>

#ifdef MORDRED_VFS_TESTING
static CiTestHook test_hook;
__declspec(dllexport) void mordred_vfs_test_hook(CiTestHook hook) { test_hook=hook; }
int ci_test_stage(int stage, HANDLE handle) { return test_hook ? test_hook(stage,handle) : 0; }
#endif

static int equal(const wchar_t *a, const wchar_t *b) {
  return CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL;
}

static int leaf(const wchar_t *text, size_t n) {
  size_t i, base = 0;
  wchar_t name[CI_PATH];
  if (!n || n >= CI_PATH || text[n-1] == L'.' || text[n-1] == L' ') return 0;
  for (i = 0; i < n; i++) {
    wchar_t c = text[i];
    if (c < 32 || wcschr(L":<>\"|?*%", c)) return 0;
  }
  while (base < n && text[base] != L'.') base++;
  memcpy(name, text, base * sizeof(wchar_t));
  name[base] = 0;
  if (equal(name,L"CON") || equal(name,L"PRN") || equal(name,L"AUX") || equal(name,L"NUL") ||
      equal(name,L"CONIN$") || equal(name,L"CONOUT$")) return 0;
  if (base == 4 && (CompareStringOrdinal(name,3,L"COM",3,TRUE)==CSTR_EQUAL ||
                   CompareStringOrdinal(name,3,L"LPT",3,TRUE)==CSTR_EQUAL) &&
      ((name[3]>=L'1' && name[3]<=L'9') || name[3]==0xB9 || name[3]==0xB2 || name[3]==0xB3)) return 0;
  return 1;
}

int ci_path(const wchar_t *input, wchar_t output[CI_PATH]) {
  size_t n, i, start;
  if (!input) return SQLITE_CANTOPEN;
  n = wcsnlen(input, CI_PATH);
  if (n < 4 || n >= CI_PATH || !((input[0]>=L'A' && input[0]<=L'Z') ||
      (input[0]>=L'a' && input[0]<=L'z')) || input[1] != L':' ||
      (input[2] != L'\\' && input[2] != L'/')) return SQLITE_CANTOPEN;
  for (i=0; i<=n; i++) output[i] = input[i]==L'/' ? L'\\' : input[i];
  start=3;
  for (i=3; i<=n; i++) {
    if (output[i]==L'\\' || !output[i]) {
      if (!leaf(output+start,i-start)) return SQLITE_CANTOPEN;
      start=i+1;
    }
  }
  return SQLITE_OK;
}

int ci_utf8(const char *input, wchar_t output[CI_PATH]) {
  wchar_t wide[CI_PATH];
  if (!input || !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input,-1,wide,CI_PATH)) return SQLITE_CANTOPEN;
  return ci_path(wide,output);
}

static int current_sid(PSID *sid) {
  HANDLE token = NULL, impersonation = NULL;
  DWORD length = 0;
  TOKEN_USER *user;
  int ok = 0;
  *sid = NULL;
  /* An impersonation context would make process-user ownership ambiguous. */
  if (OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&impersonation)) {
    CloseHandle(impersonation);
    return 0;
  }
  if (GetLastError()!=ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return 0;
  GetTokenInformation(token,TokenUser,NULL,0,&length);
  user=(TOKEN_USER *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,length);
  if (user && GetTokenInformation(token,TokenUser,user,length,&length) && IsValidSid(user->User.Sid)) {
    DWORD size=GetLengthSid(user->User.Sid);
    *sid=LocalAlloc(LMEM_FIXED,size);
    if (*sid && CopySid(size,*sid,user->User.Sid)) ok=1;
  }
  if (user) HeapFree(GetProcessHeap(),0,user);
  CloseHandle(token);
  if (!ok && *sid) { LocalFree(*sid); *sid=NULL; }
  return ok;
}

static int trustee(CiRoot *r, PSID sid) {
  if (EqualSid(sid,r->user)) return 1;
  if (EqualSid(sid,r->system)) return 2;
  if (EqualSid(sid,r->admins)) return 4;
  if (EqualSid(sid,r->installer)) return 8;
  return 0;
}

static int acl_check(CiRoot *r, HANDLE handle, int private_acl) {
  PSECURITY_DESCRIPTOR sd=NULL;
  PSID owner=NULL;
  PACL acl=NULL;
  SECURITY_DESCRIPTOR_CONTROL control;
  DWORD revision, i, found=0;
  int ok=0;
  GENERIC_MAPPING mapping={FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};
  DWORD forbidden=DELETE|WRITE_DAC|WRITE_OWNER|FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD|FILE_WRITE_EA|FILE_ADD_FILE;
  if (GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                      &owner,NULL,&acl,NULL,&sd)!=ERROR_SUCCESS) return 0;
  if (!owner || !IsValidSid(owner) || !acl || !IsValidAcl(acl) ||
      !GetSecurityDescriptorControl(sd,&control,&revision)) goto done;
  if (private_acl) {
    if (!EqualSid(owner,r->user) || !(control&SE_DACL_PROTECTED) || acl->AceCount!=3) goto done;
  } else if (!trustee(r,owner)) goto done;
  for (i=0; i<acl->AceCount; i++) {
    ACCESS_ALLOWED_ACE *ace;
    PSID sid;
    DWORD mask;
    int trusted;
    if (!GetAce(acl,i,(void **)&ace) ||
        (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceType!=ACCESS_DENIED_ACE_TYPE) ||
        ace->Header.AceFlags & ~0x1f || ace->Header.AceSize < sizeof(ACCESS_ALLOWED_ACE)) goto done;
    sid=(PSID)&ace->SidStart;
    if (!IsValidSid(sid) || GetLengthSid(sid) > ace->Header.AceSize - offsetof(ACCESS_ALLOWED_ACE,SidStart)) goto done;
    mask=ace->Mask;
    MapGenericMask(&mask,&mapping);
    trusted=trustee(r,sid);
    if (private_acl) {
      if (ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags ||
          !(trusted&7) || (found & (DWORD)trusted) || mask!=FILE_ALL_ACCESS) goto done;
      found|=(DWORD)trusted;
    } else {
      if (ace->Header.AceFlags&INHERIT_ONLY_ACE || ace->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
      if (EqualSid(sid,r->owner_rights)) trusted=trustee(r,owner);
      if ((mask&~FILE_ALL_ACCESS) || (!trusted && (mask&forbidden))) goto done;
    }
  }
  ok=!private_acl || found==7;
done:
  LocalFree(sd);
  return ok;
}

static int identity_equal(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b) {
  return a->dwVolumeSerialNumber==b->dwVolumeSerialNumber &&
         a->nFileIndexHigh==b->nFileIndexHigh && a->nFileIndexLow==b->nFileIndexLow;
}

static int metadata(CiRoot *r, HANDLE handle, int directory, const wchar_t *path,
                    BY_HANDLE_FILE_INFORMATION *info, int private_acl) {
  wchar_t actual[CI_NATIVE_PATH];
  DWORD length;
  if (!GetFileInformationByHandle(handle,info) || info->dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT ||
      (!!(info->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))!=directory ||
      (!directory && info->nNumberOfLinks!=1)) return 0;
  length=GetFinalPathNameByHandleW(handle,actual,CI_NATIVE_PATH,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);
  if (!length || length>=CI_NATIVE_PATH || (path && !equal(path,actual))) return 0;
  if (r->count && info->dwVolumeSerialNumber!=r->pins[0].identity.dwVolumeSerialNumber) return 0;
  return acl_check(r,handle,private_acl);
}

static int pin_open(CiRoot *r, CiPin *pin, const wchar_t *path, int private_acl) {
  DWORD n;
  memset(pin,0,sizeof(*pin));
  pin->handle=CreateFileW(path,READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
  if (pin->handle==INVALID_HANDLE_VALUE) { pin->handle=NULL; return SQLITE_CANTOPEN; }
  pin->private_acl=private_acl;
  n=GetFinalPathNameByHandleW(pin->handle,pin->path,CI_NATIVE_PATH,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);
  if (!n || n>=CI_NATIVE_PATH || !metadata(r,pin->handle,1,NULL,&pin->identity,private_acl)) goto failed;
  /* A canonical native child must be exactly the requested child, not a short
   * alias or reparse resolution. The initial drive root is checked separately. */
  if (wcslen(path)>3 && !equal(path,pin->path)) goto failed;
  return SQLITE_OK;
failed:
  CloseHandle(pin->handle); pin->handle=NULL;
  return SQLITE_CANTOPEN;
}

static int pin_check(CiRoot *r, CiPin *pin) {
  BY_HANDLE_FILE_INFORMATION now;
  return metadata(r,pin->handle,1,pin->path,&now,pin->private_acl) && identity_equal(&pin->identity,&now);
}

int ci_root_open(CiRoot *r, const wchar_t *path) {
  wchar_t drive[4], target[CI_NATIVE_PATH], fs[32], native[CI_NATIVE_PATH], sddl[512];
  wchar_t *sidtext=NULL;
  size_t start, end, at;
  int rc=SQLITE_CANTOPEN;
  if (ci_path(path,r->path)!=SQLITE_OK || !current_sid(&r->user) ||
      !ConvertStringSidToSidW(L"S-1-5-18",&r->system) ||
      !ConvertStringSidToSidW(L"S-1-5-32-544",&r->admins) ||
      !ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",&r->installer) ||
      !ConvertStringSidToSidW(L"S-1-3-4",&r->owner_rights)) goto done;
  memcpy(drive,r->path,3*sizeof(wchar_t)); drive[3]=0;
  if (GetDriveTypeW(drive)!=DRIVE_FIXED) goto done;
  drive[2]=0;
  if (!QueryDosDeviceW(drive,target,CI_NATIVE_PATH) || wcsncmp(target,L"\\Device\\HarddiskVolume",22)) goto done;
  for (at=22; target[at]; at++) if (target[at]<L'0' || target[at]>L'9') goto done;
  if (at==22) goto done;
  drive[2]=L'\\';
  if (pin_open(r,&r->pins[0],drive,0)!=SQLITE_OK) goto done;
  r->count=1;
  if (!GetVolumeInformationByHandleW(r->pins[0].handle,NULL,0,NULL,NULL,NULL,fs,32) || wcscmp(fs,L"NTFS")) goto done;
  for (start=3; r->path[start]; start=end+1) {
    for (end=start; r->path[end] && r->path[end]!=L'\\'; end++) {}
    if (r->count==CI_DEPTH) goto done;
    wcscpy_s(native,CI_NATIVE_PATH,r->pins[r->count-1].path);
    at=wcslen(native);
    if (native[at-1]!=L'\\') native[at++]=L'\\';
    memcpy(native+at,r->path+start,(end-start)*sizeof(wchar_t)); native[at+end-start]=0;
    if (pin_open(r,&r->pins[r->count],native,r->path[end]==0)!=SQLITE_OK) goto done;
    r->count++;
    if (!r->path[end]) break;
  }
  if (!ConvertSidToStringSidW(r->user,&sidtext)) goto done;
  if (swprintf_s(sddl,512,L"O:%lsD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%ls)",sidtext,sidtext)<0 ||
      !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&r->creation,NULL)) goto done;
  rc=SQLITE_OK;
done:
  if (sidtext) LocalFree(sidtext);
  if (rc!=SQLITE_OK) ci_root_close(r);
  return rc;
}

void ci_root_close(CiRoot *r) {
  while (r->count) CloseHandle(r->pins[--r->count].handle);
  if (r->user) LocalFree(r->user);
  if (r->system) LocalFree(r->system);
  if (r->admins) LocalFree(r->admins);
  if (r->installer) LocalFree(r->installer);
  if (r->owner_rights) LocalFree(r->owner_rights);
  if (r->creation) LocalFree(r->creation);
}

int ci_root_check(CiRoot *r) {
  int i, same;
  PSID user=NULL;
  if (!current_sid(&user)) return SQLITE_IOERR_ACCESS;
  same=EqualSid(user,r->user); LocalFree(user);
  if (!same) return SQLITE_IOERR_ACCESS;
  for (i=0; i<r->count; i++) if (!pin_check(r,&r->pins[i])) return SQLITE_IOERR_ACCESS;
  return SQLITE_OK;
}

int ci_contains(CiRoot *r, const wchar_t *path) {
  size_t n=wcslen(r->path);
  return wcslen(path)>n && path[n]==L'\\' && CompareStringOrdinal(r->path,(int)n,path,(int)n,TRUE)==CSTR_EQUAL;
}

int ci_open(CiRoot *r, const wchar_t *path, int create, int readonly, int deleting, CiFile *f) {
  size_t start, end, at;
  int rc=SQLITE_CANTOPEN, created=0;
  SECURITY_ATTRIBUTES sa={sizeof(sa),r->creation,FALSE};
  DWORD access=GENERIC_READ|READ_CONTROL|(readonly ? 0 : GENERIC_WRITE)|(deleting ? DELETE : 0);
  memset(f,0,sizeof(*f)); f->root=r; f->readonly=readonly;
  if (!ci_contains(r,path) || ci_root_check(r)!=SQLITE_OK) return SQLITE_CANTOPEN;
  wcscpy_s(f->path,CI_NATIVE_PATH,r->pins[r->count-1].path);
  start=wcslen(r->path)+1;
  for (;;) {
    for (end=start; path[end] && path[end]!=L'\\'; end++) {}
    at=wcslen(f->path);
    if (at+end-start+2>CI_NATIVE_PATH) goto failed;
    f->path[at++]=L'\\';
    memcpy(f->path+at,path+start,(end-start)*sizeof(wchar_t)); f->path[at+end-start]=0;
    if (!path[end]) break;
    if (f->count==CI_DEPTH || pin_open(r,&f->pins[f->count],f->path,1)!=SQLITE_OK) goto failed;
    f->count++; start=end+1;
  }
  /* CREATE_NEW never touches a pre-existing file. If it loses a race, open
   * that existing object with OPEN_REPARSE_POINT and validate THIS handle.
   * Every creation has a protected, owner-explicit DACL at first visibility. */
  if (create) {
    f->handle=CreateFileW(f->path,access,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if (f->handle!=INVALID_HANDLE_VALUE) created=1;
    else if (GetLastError()!=ERROR_FILE_EXISTS && GetLastError()!=ERROR_ALREADY_EXISTS) goto failed;
  }
  if (!created) f->handle=CreateFileW(f->path,access,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,
                                     FILE_FLAG_OPEN_REPARSE_POINT,NULL);
  if (f->handle==INVALID_HANDLE_VALUE) {
    DWORD error=GetLastError(); f->handle=NULL;
    if (error==ERROR_FILE_NOT_FOUND) rc=SQLITE_NOTFOUND;
    goto failed;
  }
  if (created) {
    InterlockedIncrement64(&r->created);
    if (ci_test_stage(CI_AFTER_CREATE,f->handle)) goto failed;
  }
  if (!metadata(r,f->handle,0,f->path,&f->identity,1)) goto failed;
  if (created) InterlockedIncrement64(&r->private_created);
  if (ci_check(f)!=SQLITE_OK) goto failed;
  InterlockedIncrement64(&r->data_opens);
  return SQLITE_OK;
failed:
  ci_close(f);
  return rc;
}

int ci_check(CiFile *f) {
  int i;
  BY_HANDLE_FILE_INFORMATION now;
  if (ci_root_check(f->root)!=SQLITE_OK) return SQLITE_IOERR_ACCESS;
  for (i=0; i<f->count; i++) if (!pin_check(f->root,&f->pins[i])) return SQLITE_IOERR_ACCESS;
  if (!metadata(f->root,f->handle,0,f->path,&now,1) || !identity_equal(&f->identity,&now)) return SQLITE_IOERR_ACCESS;
  return SQLITE_OK;
}

int ci_close(CiFile *f) {
  int rc=SQLITE_OK;
  if (f->handle && f->handle!=INVALID_HANDLE_VALUE && !CloseHandle(f->handle)) rc=SQLITE_IOERR_CLOSE;
  f->handle=NULL;
  while (f->count) if (!CloseHandle(f->pins[--f->count].handle)) rc=SQLITE_IOERR_CLOSE;
  return rc;
}

int ci_delete(CiFile *f) {
  FILE_DISPOSITION_INFO disposition={TRUE};
  if (ci_check(f)!=SQLITE_OK || ci_test_stage(CI_BEFORE_DELETE,f->handle)) return SQLITE_IOERR_DELETE;
  return SetFileInformationByHandle(f->handle,FileDispositionInfo,&disposition,sizeof(disposition)) ? SQLITE_OK : SQLITE_IOERR_DELETE;
}

int ci_size(CiFile *f, sqlite3_int64 *size) {
  LARGE_INTEGER value;
  if (ci_check(f)!=SQLITE_OK || !GetFileSizeEx(f->handle,&value)) return SQLITE_IOERR_FSTAT;
  *size=value.QuadPart; return SQLITE_OK;
}

int ci_truncate(CiFile *f, sqlite3_int64 size) {
  FILE_END_OF_FILE_INFO value;
  value.EndOfFile.QuadPart=size;
  if (size<0 || ci_check(f)!=SQLITE_OK || f->readonly || ci_test_stage(CI_BEFORE_TRUNCATE,f->handle)) return SQLITE_IOERR_TRUNCATE;
  InterlockedIncrement64(&f->root->truncates);
  return SetFileInformationByHandle(f->handle,FileEndOfFileInfo,&value,sizeof(value)) ? SQLITE_OK : SQLITE_IOERR_TRUNCATE;
}

int ci_read(CiFile *f, void *buffer, int count, sqlite3_int64 offset) {
  DWORD got=0;
  OVERLAPPED position;
  memset(&position,0,sizeof(position));
  if (count<0 || offset<0 || ci_check(f)!=SQLITE_OK || ci_test_stage(CI_BEFORE_READ,f->handle)) return SQLITE_IOERR_READ;
  position.Offset=(DWORD)offset; position.OffsetHigh=(DWORD)((uint64_t)offset>>32);
  if (!ReadFile(f->handle,buffer,(DWORD)count,&got,&position) && GetLastError()!=ERROR_HANDLE_EOF) return SQLITE_IOERR_READ;
  if (got!=(DWORD)count) {
    memset((char *)buffer+got,0,(size_t)count-got);
    return SQLITE_IOERR_SHORT_READ;
  }
  return SQLITE_OK;
}

int ci_write(CiFile *f, const void *buffer, int count, sqlite3_int64 offset) {
  DWORD wrote=0;
  OVERLAPPED position;
  memset(&position,0,sizeof(position));
  if (count<0 || offset<0 || ci_check(f)!=SQLITE_OK || f->readonly || ci_test_stage(CI_BEFORE_WRITE,f->handle)) return SQLITE_IOERR_WRITE;
  position.Offset=(DWORD)offset; position.OffsetHigh=(DWORD)((uint64_t)offset>>32);
  if (!WriteFile(f->handle,buffer,(DWORD)count,&wrote,&position) || wrote!=(DWORD)count) return SQLITE_IOERR_WRITE;
  return SQLITE_OK;
}

int ci_sync(CiFile *f) {
  if (ci_check(f)!=SQLITE_OK || ci_test_stage(CI_BEFORE_SYNC,f->handle)) return SQLITE_IOERR_FSYNC;
  InterlockedIncrement64(&f->root->syncs);
  return FlushFileBuffers(f->handle) ? SQLITE_OK : SQLITE_IOERR_FSYNC;
}

int ci_lock(CiFile *f, DWORD offset, DWORD length, int exclusive) {
  OVERLAPPED position;
  DWORD error;
  memset(&position,0,sizeof(position)); position.Offset=offset;
  if (ci_check(f)!=SQLITE_OK || ci_test_stage(CI_BEFORE_LOCK,f->handle)) return SQLITE_IOERR_LOCK;
  if (LockFileEx(f->handle,LOCKFILE_FAIL_IMMEDIATELY|(exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0),0,length,0,&position)) return SQLITE_OK;
  error=GetLastError();
  return error==ERROR_LOCK_VIOLATION || error==ERROR_IO_PENDING ? SQLITE_BUSY : SQLITE_IOERR_LOCK;
}

int ci_unlock(CiFile *f, DWORD offset, DWORD length) {
  OVERLAPPED position;
  memset(&position,0,sizeof(position)); position.Offset=offset;
  /* Cleanup still releases locks after policy revocation; it never reads or
   * writes sensitive content and must not strand the other processes. */
  return UnlockFileEx(f->handle,0,length,0,&position) ? SQLITE_OK : SQLITE_IOERR_UNLOCK;
}
