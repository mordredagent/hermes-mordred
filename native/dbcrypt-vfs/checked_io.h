#ifndef MORDRED_CHECKED_IO_H
#define MORDRED_CHECKED_IO_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "sqlite3.h"

#ifndef _WIN64
#error The checked Windows VFS requires the qualified x64 target.
#endif

#define CI_PATH 240
#define CI_NATIVE_PATH 320
#define CI_DEPTH 120

typedef struct CiPin {
  HANDLE handle;
  BY_HANDLE_FILE_INFORMATION identity;
  wchar_t path[CI_NATIVE_PATH];
  int private_acl;
} CiPin;

typedef struct CiRoot {
  struct CiRoot *next;
  uint64_t token;
  LONG files;
  wchar_t path[CI_PATH];
  CiPin pins[CI_DEPTH];
  int count;
  PSID user, system, admins, installer, owner_rights;
  PSECURITY_DESCRIPTOR creation;
  volatile LONG64 opens, deletes, maps, unmaps, syncs, truncates;
  volatile LONG64 created, private_created, data_opens;
} CiRoot;

typedef struct CiFile {
  HANDLE handle;
  CiRoot *root;
  BY_HANDLE_FILE_INFORMATION identity;
  wchar_t path[CI_NATIVE_PATH];
  CiPin pins[CI_DEPTH];
  int count;
  int readonly;
} CiFile;

/* No function in this module delegates a pathname or handle to another VFS. */
int ci_path(const wchar_t *input, wchar_t output[CI_PATH]);
int ci_utf8(const char *input, wchar_t output[CI_PATH]);
int ci_root_open(CiRoot *root, const wchar_t *path);
void ci_root_close(CiRoot *root);
int ci_root_check(CiRoot *root);
int ci_contains(CiRoot *root, const wchar_t *path);
int ci_open(CiRoot *root, const wchar_t *path, int create, int readonly, int deleting, CiFile *file);
int ci_check(CiFile *file);
int ci_close(CiFile *file);
int ci_delete(CiFile *file);
int ci_size(CiFile *file, sqlite3_int64 *size);
int ci_truncate(CiFile *file, sqlite3_int64 size);
int ci_read(CiFile *file, void *buffer, int count, sqlite3_int64 offset);
int ci_write(CiFile *file, const void *buffer, int count, sqlite3_int64 offset);
int ci_sync(CiFile *file);
int ci_lock(CiFile *file, DWORD offset, DWORD length, int exclusive);
int ci_unlock(CiFile *file, DWORD offset, DWORD length);

/* Absent from production DLLs. The qualification build can fail individual
 * boundaries and inspect the actual creation handle before the first write.
 * Set/clear only with no concurrent VFS call; never retain a borrowed handle. */
#ifdef MORDRED_VFS_TESTING
typedef int (__cdecl *CiTestHook)(int stage, HANDLE handle);
int ci_test_stage(int stage, HANDLE handle);
#else
static __inline int ci_test_stage(int stage, HANDLE handle) {
  (void)stage; (void)handle; return 0;
}
#endif
#define CI_AFTER_CREATE 1
#define CI_BEFORE_READ 2
#define CI_BEFORE_WRITE 3
#define CI_BEFORE_TRUNCATE 4
#define CI_BEFORE_SYNC 5
#define CI_BEFORE_MAP 6
#define CI_BEFORE_LOCK 7
#define CI_BEFORE_DELETE 8
#endif
