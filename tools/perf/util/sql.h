#include "evsel.h"
#include <assert.h>
#include <sqlite3.h>

#define CALL_SQLITE(f,d)                                         \
     {                                                           \
         int ii;                                                  \
         ii = sqlite3_ ## f;                                      \
         if (ii != SQLITE_OK) {                                   \
             fprintf (stderr, "%s failed with status %d: %s\n",  \
                      #f, ii, sqlite3_errmsg (d));                \
             assert(false);                                      \
         }                                                       \
     }                                                           \

#define CALL_SQLITE_EXPECT(f,x,d)                               \
    {                                                           \
        int ii;                                                  \
        ii = sqlite3_ ## f;                                      \
        if (ii != SQLITE_ ## x) {                                \
            fprintf (stderr, "%s failed with status %d: %s\n",  \
                     #f, ii, sqlite3_errmsg (d));                \
            assert(false);                                      \
        }                                                       \
    }                                                           \

#define CALL_SQLITE_ASSERT(f)                                    \
     {                                                           \
         int ii;                                                 \
         ii = sqlite3_ ## f;                                     \
         if (ii != SQLITE_OK) {                                  \
             fprintf (stderr, "%s failed with status %d\n",      \
                      #f, ii);                                   \
             assert (false);                                     \
         }                                                       \
     }                                                           \

struct ev2stmt {
  sqlite3_stmt *stmt_sample;
  struct perf_evsel *evsel;
};

struct perf_sql {
  sqlite3 *db;
  sqlite3_stmt *stmt_attr;
  sqlite3_stmt *stmt_ip;
  sqlite3_stmt *stmt_regs;
  sqlite3_stmt *stmt_branch_entry;
  u8 nr;
  struct ev2stmt sample[0];
};

static inline void perf_sql__exec(sqlite3 *db, const char *stmt) {
  char *zErrMsg = NULL;
  //printf("%s\n",stmt);
  CALL_SQLITE(exec(db, stmt, NULL, NULL, &zErrMsg),db);
}

struct perf_sql *perf_sql__new(const char *name, struct perf_evlist *evlist);

sqlite3_stmt *perf_sql__get_stmt(struct perf_sql *S, struct perf_evsel *evsel);
int perf_sql__get_attr_id(struct perf_sql *S, struct perf_evsel *evsel);
void perf_sql__bind_sample_int(struct perf_sql *S, struct perf_evsel *evesel,
                               const char *zName, int v);
void perf_sql__bind_sample_int64(struct perf_sql *S, struct perf_evsel *evesel,
                          const char *namedparam, sqlite3_int64 v);
void perf_sql__bind_sample_text(struct perf_sql *S, struct perf_evsel *evesel,
                         const char *namedparam, const char *v);

void perf_sql__bind_int(sqlite3_stmt *stmt, const char *zName, int v);

void perf_sql__bind_int64(sqlite3_stmt *stmt,
                          const char *namedparam, sqlite3_int64 v);

void perf_sql__bind_text(sqlite3_stmt *stmt,
                         const char *namedparam, const char *v);

void perf_sql__insert_ip(struct perf_sql *S, struct perf_evsel *evsel,
                         struct perf_sample *sample,
			                   struct addr_location *al);

void perf_sql__insert_callchain(struct perf_sql *S, struct perf_evsel *evsel,
                   struct perf_sample *sample,
			  struct addr_location *al, unsigned int stack_depth);

void perf_sql__insert_regs(struct perf_sql *S, struct perf_evsel *evsel,
        union perf_event *event __maybe_unused,
			  struct perf_sample *sample,
			  struct thread *thread __maybe_unused,
			  struct perf_event_attr *attr, const char *zName);

void perf_sql__insert_branch_stack(struct perf_sql *S, struct perf_evsel *evsel,
        union perf_event *event __maybe_unused,
			  struct perf_sample *sample,
			  struct thread *thread __maybe_unused,
			  struct perf_event_attr *attr __maybe_unused);

