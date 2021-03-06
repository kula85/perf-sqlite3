#include "callchain.h"
#include "evlist.h"
#include "thread.h"
#include "machine.h"
#include "sql.h"

// TODO add tracepoints support

static void new_table_attr(struct perf_sql *S) {
  const char *table = \
          "CREATE TABLE attr(" \
                "id integer primary key," \
                "type integer," \
                "size integer," \
                "config integer," \
                "period integer," \
                "sample_type integer," \
                "read_format integer," \
                "flags integer," \
                "wakeup integer," \
                "bp_type integer," \
                "config1 integer," \
                "config2 integer," \
                "branch_sample_type integer," \
                "sample_regs_user integer," \
                "sample_stack_user integer," \
                "__reserved_2 integer," \
                "sample_regs_intr integer," \
                "unique(id,type,size,config,period,sample_type,read_format,flags,wakeup,bp_type,config1,config2,branch_sample_type,sample_regs_user,sample_stack_user,__reserved_2,sample_regs_intr));";
  const char *stmt = \
          "insert or ignore into attr values(" \
          "null,@type,@size,@config,@period,@sample_type,@read_format,@flags,@wakeup,@bp_type,@config1,@config2,@branch_sample_type,@sample_regs_user,@sample_stack_user,@__reserved_2,@sample_regs_intr);";
  const char *stmt_sel = \
          "select id from attr where " \
          "type = @type and " \
          "size = @size and " \
          "config = @config and " \
          "period = @period and " \
          "sample_type = @sample_type and " \
          "read_format = @read_format and " \
          "flags = @flags and " \
          "wakeup = @wakeup and " \
          "bp_type = @bp_type and " \
          "config1 = @config1 and " \
          "config2 = @config2 and " \
          "branch_sample_type = @branch_sample_type and " \
          "sample_regs_user = @sample_regs_user and " \
          "sample_stack_user = @sample_stack_user and " \
          "__reserved_2 = @__reserved_2 and " \
          "sample_regs_intr = @sample_regs_intr;";
  perf_sql__exec(S->db, table);
  CALL_SQLITE(prepare_v2(S->db, stmt,
              strlen(stmt)+1, &S->stmt_attr, NULL),S->db);
  CALL_SQLITE(prepare_v2(S->db, stmt_sel,
              strlen(stmt_sel)+1, &S->stmt_attr_sel, NULL),S->db);
}

static void new_table_ip(struct perf_sql *S) {
  const char *table = \
          "CREATE TABLE ip(" \
                "id integer primary key," \
                "ip text," \
                "sym text," \
                "off integer," \
                "dso text," \
                "srcline text," \
                "unique(ip,sym,off,dso,srcline));";
  const char *stmt = \
          "insert or ignore into ip values(null,@ip,@sym,@off,@dso,@srcline);";
  const char *stmt_sel = "select id from ip where " \
         "ip = @ip and " \
         "sym = @sym and " \
         "off is @off and " \
         "dso = @dso and " \
         "srcline is @srcline;";
  perf_sql__exec(S->db, table);
  CALL_SQLITE(prepare_v2(S->db, stmt,
              strlen(stmt)+1, &S->stmt_ip, NULL),S->db);
  CALL_SQLITE(prepare_v2(S->db, stmt_sel,
              strlen(stmt_sel)+1, &S->stmt_ip_sel, NULL),S->db);
}


// TODO relate to ip table with column(dso,offset)?
static void new_table_branch_entry(struct perf_sql *S) {
  const char *table = \
          "CREATE TABLE branch_entry(" \
                "id integer primary key,  " \
                "\"from\" integer references ip(id),        " \
                "\"to\" integer references ip(id),          " \
                "predicted text,                        " \
                "in_tx text,                         " \
                "abort text,                         " \
                "cycles integer,                        " \
                "unique(\"from\",\"to\",predicted,in_tx,abort,cycles));";
  const char *stmt = \
          "insert or ignore into branch_entry values(null,@from,@to,@predicted,@in_tx,@abort,@cycles);";
  const char *stmt_sel = \
          "select id from branch_entry where " \
          "\"from\" = @from and " \
          "\"to\" = @to and " \
          "predicted = @predicted and " \
          "in_tx = @in_tx and " \
          "abort = @abort and " \
          "cycles = @cycles;";
  perf_sql__exec(S->db, table);
  CALL_SQLITE(prepare_v2(S->db, stmt,
              strlen(stmt)+1, &S->stmt_branch_entry, NULL),S->db);
  CALL_SQLITE(prepare_v2(S->db, stmt_sel,
              strlen(stmt_sel)+1, &S->stmt_branch_entry_sel, NULL),S->db);
}

static void new_table_regs(struct perf_sql *S) {
  const char *table = \
          "CREATE TABLE regs(" \
                "id integer primaty key,     " \
                "ax integer,     " \
                "bx integer,     " \
                "cx integer,     " \
                "dx integer,     " \
                "si integer,     " \
                "di integer,     " \
                "bp integer,     " \
                "sp integer,     " \
                "ip integer,     " \
                "flags integer,  " \
                "cs integer,     " \
                "ss integer,     " \
                "ds integer,     " \
                "es integer,     " \
                "fs integer,     " \
                "gs integer,     " \
                "r8 integer,     " \
                "r9 integer,     " \
                "r10 integer,    " \
                "r11 integer,    " \
                "r12 integer,    " \
                "r13 integer,    " \
                "r14 integer,    " \
                "r15 integer,    " \
                "unique(ax,bx,cx,dx,si,di,bp,sp,ip,flags,cs,ss,ds,es,fs,gs,r8,r9,r10,r11,r12,r13,r14,r15));";
  const char *stmt = \
          "insert or ignore into regs values(null,@ax,@bx,@cx,@dx,@si,@di,@bp,@sp,@ip,@flags,@cs,@ss,@ds,@es,@fs,@gs,@r8,@r9,@r10,@r11,@r12,@r13,@r14,@r15);";
  const char *stmt_sel = "select id from regs where " \
         "ax = @ax and " \
         "bx = @bx and " \
         "cx = @cx and " \
         "dx = @dx and " \
         "si = @si and " \
         "di = @di and " \
         "bp = @bp and " \
         "sp = @sp and " \
         "ip = @ip and " \
         "flags = @flags and " \
         "cs = @cs and " \
         "ss = @ss and " \
         "ds = @ds and " \
         "es = @es and " \
         "fs = @fs and " \
         "gs = @gs and " \
         "r8 = @r8 and " \
         "r9 = @r9 and " \
         "r10 = @r10 and " \
         "r11 = @r11 and " \
         "r12 = @r12 and " \
         "r13 = @r13 and " \
         "r14 = @r14 and " \
         "r15 = @r15;";
  perf_sql__exec(S->db, table);
  CALL_SQLITE(prepare_v2(S->db, stmt,
              strlen(stmt)+1, &S->stmt_regs, NULL),S->db);
  CALL_SQLITE(prepare_v2(S->db, stmt_sel,
              strlen(stmt_sel)+1, &S->stmt_regs_sel, NULL),S->db);
}

struct perf_sql *perf_sql__new(const char *name, struct perf_evlist *evlist) {
  int FK = 0;
  int i = -1;
  struct perf_evsel *evsel = NULL;
  struct perf_sql *S = (struct perf_sql *)malloc(sizeof(*S) + evlist->nr_entries*sizeof(struct ev2stmt));
  sqlite3 **db = &S->db;

  // Open db
  CALL_SQLITE(open_v2(name, db,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL),*db);

  // Enable foreign key
  CALL_SQLITE(db_config(*db, SQLITE_DBCONFIG_ENABLE_FKEY, 1, &FK),*db);
  assert(FK == 1);

  new_table_attr(S);
  new_table_ip(S);

  S->nr = evlist->nr_entries;
	evlist__for_each(evlist, evsel) {
    char idx[8];
    char create_table_sample[1000];
    char create_stmt_sample[1000];
    struct perf_event_attr *attr = &evsel->attr;

    assert(attr->sample_type && "sample without any information? no way");
    S->sample[++i].evsel = evsel;

    // Create parent tables
    if ((attr->sample_type & PERF_SAMPLE_REGS_USER) ||
        (attr->sample_type & PERF_SAMPLE_REGS_INTR))
      new_table_regs(S);
    if (attr->sample_type & PERF_SAMPLE_BRANCH_STACK)
      new_table_branch_entry(S);

    // prepare sample table & statement
    create_table_sample[0] = '\0';
    strcat(create_table_sample, "CREATE TABLE sample");
    snprintf(idx, 8, "%d", i);
    strcat(create_table_sample, idx);
    strcat(create_table_sample, "(id integer primary key,");
    strcat(create_table_sample, "comm text,");

    create_stmt_sample[0] = '\0';
    strcat(create_stmt_sample, "insert into sample");
    strcat(create_stmt_sample, idx);
    strcat(create_stmt_sample, " values(null,@comm,");

    if (attr->sample_type & PERF_SAMPLE_TID) {
      strcat(create_table_sample, "pid integer,");
      strcat(create_stmt_sample, "@pid,");

      strcat(create_table_sample, "tid integer,");
      strcat(create_stmt_sample, "@tid,");
    }

    if (attr->sample_type & PERF_SAMPLE_ID) {
      strcat(create_table_sample, "sample_id integer,");
      strcat(create_stmt_sample, "@sample_id,");

      // TODO
      //strcat(create_table_sample, "attr_id integer references attr(id),");
      //strcat(create_stmt_sample, "@attr_id,");
    }
    if (attr->sample_type & PERF_SAMPLE_STREAM_ID) {
      strcat(create_table_sample, "stream_id integer,");
      strcat(create_stmt_sample, "@stream_id,");
    }
    if (attr->sample_type & PERF_SAMPLE_CPU) {
      strcat(create_table_sample, "cpu integer,");
      strcat(create_stmt_sample, "@cpu,");
    }
    if (attr->sample_type & PERF_SAMPLE_TIME) {
      strcat(create_table_sample, "time integer,");
      strcat(create_stmt_sample, "@time,");
    }
    if (attr->sample_type & PERF_SAMPLE_PERIOD) {
      strcat(create_table_sample, "period integer,");
      strcat(create_stmt_sample, "@period,");
    }
    strcat(create_table_sample, "event_name text,");
    strcat(create_stmt_sample, "@event_name,");
    if (attr->sample_type & PERF_SAMPLE_IP) {
      strcat(create_table_sample, "ip_id integer references ip(id),");
      strcat(create_stmt_sample, "@ip_id,");
    }
    if (attr->sample_type & PERF_SAMPLE_CALLCHAIN) {
      strcat(create_table_sample, "callchain text,");
      strcat(create_stmt_sample, "@callchain,");
    }
    if (attr->sample_type & PERF_SAMPLE_REGS_USER) {
      strcat(create_table_sample, "uregs_id integer references regs(id),");
      strcat(create_stmt_sample, "@uregs_id");
    }
    if (attr->sample_type & PERF_SAMPLE_REGS_INTR) {
      strcat(create_table_sample, "iregs_id integer references regs(id),");
      strcat(create_stmt_sample, "@iregs_id,");
    }
    if (attr->sample_type & PERF_SAMPLE_BRANCH_STACK) {
      strcat(create_table_sample, "brstack text,");
      strcat(create_stmt_sample, "@brstack,");
    }
    if (attr->sample_type & PERF_SAMPLE_WEIGHT) {
      strcat(create_table_sample, "weight integer,");
      strcat(create_stmt_sample, "@weight,");
    }
    if (attr->sample_type & PERF_SAMPLE_DATA_SRC) {
      strcat(create_table_sample, "data_src integer,");
      strcat(create_stmt_sample, "@data_src,");
    }
    if (attr->sample_type & PERF_SAMPLE_TRANSACTION) {
      strcat(create_table_sample, "transaction integer,");
      strcat(create_stmt_sample, "@transaction,");
    }
    create_table_sample[strlen(create_table_sample) - 1] = ')';
    strcat(create_table_sample, ";");
    create_stmt_sample[strlen(create_stmt_sample) - 1] = ')';
    strcat(create_stmt_sample, ";");

    // Create table & statements
    perf_sql__exec(*db, create_table_sample);
    CALL_SQLITE(prepare_v2(*db, create_stmt_sample,
          strlen(create_stmt_sample)+1, &S->sample[i].stmt_sample, NULL),*db);
  }

  // TODO
  // Insert attr data

  return S;
}

// TODO check if int64 to u64 conversion succeed
void perf_sql__bind_int64(sqlite3_stmt *stmt, const char *zName, sqlite3_int64 v) {
  int idx = sqlite3_bind_parameter_index(stmt, zName);
  if (idx)
    CALL_SQLITE_ASSERT(bind_int64(stmt, idx, v));
}

void perf_sql__bind_int(sqlite3_stmt *stmt, const char *zName, int v) {
  int idx = sqlite3_bind_parameter_index(stmt, zName);
  if (idx)
    CALL_SQLITE_ASSERT(bind_int(stmt, idx, v));
}

void perf_sql__bind_text(sqlite3_stmt *stmt, const char *zName, const char *v) {
  int idx = sqlite3_bind_parameter_index(stmt, zName);
  if (idx)
    CALL_SQLITE_ASSERT(bind_text(stmt, idx, v, -1, SQLITE_STATIC));
}

static void perf_sql__bind_text_transient(sqlite3_stmt *stmt, const char *zName, const char *v) {
  int idx = sqlite3_bind_parameter_index(stmt, zName);
  if (idx)
    CALL_SQLITE_ASSERT(bind_text(stmt, idx, v, -1, SQLITE_TRANSIENT));
}

sqlite3_stmt *perf_sql__get_stmt(struct perf_sql *S, struct perf_evsel *evsel) {
  u8 i = 0;
  for(; i < S->nr; ++i) {
    struct ev2stmt *e = &S->sample[i];
    if (e->evsel == evsel)
      return e->stmt_sample;
  }
  assert(false && "evsel not exist");
  return NULL;
}

int perf_sql__get_attr_id(struct perf_sql *S, struct perf_evsel *evsel) {
  int i = 0;
  for(; i < S->nr; ++i) {
    struct ev2stmt *e = &S->sample[i];
    if (e->evsel == evsel)
      return i;
  }
  assert(false && "evsel not exist");
  return 0;
}

void perf_sql__bind_sample_int(struct perf_sql *S, struct perf_evsel *evsel,
                               const char *zName, int v) {
  sqlite3_stmt *stmt = perf_sql__get_stmt(S, evsel);
  perf_sql__bind_int(stmt, zName, v);
}
void perf_sql__bind_sample_int64(struct perf_sql *S, struct perf_evsel *evsel,
                          const char *zName, sqlite3_int64 v) {
  sqlite3_stmt *stmt = perf_sql__get_stmt(S, evsel);
  perf_sql__bind_int64(stmt, zName, v);
}
void perf_sql__bind_sample_text(struct perf_sql *S, struct perf_evsel *evsel,
                         const char *zName, const char *v) {
  sqlite3_stmt *stmt = perf_sql__get_stmt(S, evsel);
  perf_sql__bind_text(stmt, zName, v);
}

#define BIND_INSERT_AND_SELECT(__f,__a1,__a2,__a3) \
  do {  \
    perf_sql__bind_##__f(__a1, __a2, __a3);  \
    perf_sql__bind_##__f(__a1 ## _sel, __a2, __a3); \
  } while(0)

static void perf_sql__bind_symname_offs(struct perf_sql *S,
            const struct symbol *sym,
				    const struct addr_location *al)
{
	unsigned long offset;

	if (sym && sym->name) {
    BIND_INSERT_AND_SELECT(text, S->stmt_ip, "@sym", sym->name);
   // printf("%s\n",sym->name);
		if (al) {
			if (al->addr < sym->end)
				offset = al->addr - sym->start;
			else
				offset = al->addr - al->map->start - sym->start;
      BIND_INSERT_AND_SELECT(int64, S->stmt_ip, "@off", offset);
     // printf("%lu\n",offset);
		}
	} else
    BIND_INSERT_AND_SELECT(text, S->stmt_ip, "@sym", "[unknown]");
}

static void perf_sql__bind_dsoname(struct perf_sql *S, struct map *map)
{
	const char *dsoname = "[unknown]";

	if (map && map->dso && (map->dso->name || map->dso->long_name)) {
		if (symbol_conf.show_kernel_path && map->dso->long_name)
			dsoname = map->dso->long_name;
		else if (map->dso->name)
			dsoname = map->dso->name;
	}

  BIND_INSERT_AND_SELECT(text, S->stmt_ip, "@dso", dsoname);
 // printf("%s\n",dsoname);
}

static void perf_sql__bind_srcline(struct perf_sql *S, struct map *map, u64 addr)
{
	char *srcline;

	if (map && map->dso) {
		srcline = get_srcline(map->dso,
				      map__rip_2objdump(map, addr), NULL, true);
		if (srcline != SRCLINE_UNKNOWN) {
      BIND_INSERT_AND_SELECT(text_transient, S->stmt_ip, "@srcline", srcline);
     // printf("%s\n",srcline);
    }
		free_srcline(srcline);
	}
}


void perf_sql__insert_ip(struct perf_sql *S, struct perf_evsel *evsel,
                         struct perf_sample *sample,
			                   struct addr_location *al)
{
  sqlite3_int64 rowid = 0;
  char *ipstr = NULL;

  if (al->sym && al->sym->ignore)
    return;

  ipstr = sqlite3_mprintf("%" PRIx64, sample->ip);
  BIND_INSERT_AND_SELECT(text_transient, S->stmt_ip, "@ip", ipstr);
  sqlite3_free(ipstr);
  perf_sql__bind_symname_offs(S, al->sym, al);
  perf_sql__bind_dsoname(S, al->map);
  perf_sql__bind_srcline(S, al->map, al->addr);

  CALL_SQLITE_EXPECT(step(S->stmt_ip),DONE,S->db);
  CALL_SQLITE(reset(S->stmt_ip),S->db);
  CALL_SQLITE(clear_bindings(S->stmt_ip),S->db);

  CALL_SQLITE_EXPECT(step(S->stmt_ip_sel),ROW,S->db);
  rowid = sqlite3_column_int64(S->stmt_ip_sel, 0);
  perf_sql__bind_sample_int64(S, evsel, "@ip_id", rowid);

  CALL_SQLITE(reset(S->stmt_ip_sel),S->db);
  CALL_SQLITE(clear_bindings(S->stmt_ip_sel),S->db);
}

void perf_sql__insert_callchain(struct perf_sql *S, struct perf_evsel *evsel,
                   struct perf_sample *sample,
			  struct addr_location *al, unsigned int stack_depth)
{
  sqlite3_stmt *stmt_sample = perf_sql__get_stmt(S, evsel);
  int idx = sqlite3_bind_parameter_index(stmt_sample, "@callchain");
	struct callchain_cursor_node *node;
  sqlite3_int64 rowid = 0;
  const int intlen = 66;
  char rowidstr[intlen];
  struct addr_location node_al;

  char *callchain_val = calloc(1, stack_depth*intlen);
  callchain_val[0] = '\0';

	if (!idx)
    return;

  if (thread__resolve_callchain(al->thread, evsel,
              sample, NULL, NULL,
              stack_depth) != 0) {
    if (verbose)
      error("Failed to resolve callchain. Skipping\n");
    return;
  }
  callchain_cursor_commit(&callchain_cursor);

  node_al = *al;

  while (stack_depth) {
    u64 addr = 0;
    char *ipstr = NULL;

    node = callchain_cursor_current(&callchain_cursor);
    if (!node)
      break;

    if (node->sym && node->sym->ignore)
      goto next;

    ipstr = sqlite3_mprintf("%" PRIx64, node->ip);
    BIND_INSERT_AND_SELECT(text_transient, S->stmt_ip, "@ip", ipstr);
    sqlite3_free(ipstr);

    if (node->map)
      addr = node->map->map_ip(node->map, node->ip);

    node_al.addr = addr;
    node_al.map  = node->map;

    perf_sql__bind_symname_offs(S, node->sym, &node_al);
    perf_sql__bind_dsoname(S, node->map);
    perf_sql__bind_srcline(S, node->map, addr);

    CALL_SQLITE_EXPECT(step(S->stmt_ip),DONE,S->db);
    CALL_SQLITE(reset(S->stmt_ip),S->db);
    CALL_SQLITE(clear_bindings(S->stmt_ip),S->db);

    CALL_SQLITE_EXPECT(step(S->stmt_ip_sel),ROW,S->db);
    rowid = sqlite3_column_int64(S->stmt_ip_sel, 0);
    snprintf(rowidstr, intlen, "%lld/", rowid);
    strcat(callchain_val, rowidstr);
    CALL_SQLITE(reset(S->stmt_ip_sel),S->db);
    CALL_SQLITE(clear_bindings(S->stmt_ip_sel),S->db);

    stack_depth--;
next:
    callchain_cursor_advance(&callchain_cursor);
  }

  CALL_SQLITE(bind_text(stmt_sample, idx, callchain_val, -1, SQLITE_STATIC),S->db);
}

// TODO
//void perf_sql__insert_attr(struct perf_sql *S, struct perf_event_attr *attr)
//{

//}

void perf_sql__insert_regs(struct perf_sql *S, struct perf_evsel *evsel,
        union perf_event *event __maybe_unused,
			  struct perf_sample *sample,
			  struct thread *thread __maybe_unused,
			  struct perf_event_attr *attr, const char *zName)
{
	struct regs_dump *regs = &sample->intr_regs;
	uint64_t mask = attr->sample_regs_intr;
	unsigned i = 0, r;
  sqlite3_int64 rowid = 0;
  sqlite3_stmt *stmt_sample = perf_sql__get_stmt(S, evsel);
  int idx = sqlite3_bind_parameter_index(stmt_sample, zName);

	if (!idx)
		return;

	for_each_set_bit(r, (unsigned long *) &mask, sizeof(mask) * 8) {
		u64 val = regs->regs[i++];
    char regname[10];
    regname[0] = '\0';
    strcat(regname, "@");
    strcat(regname, perf_reg_name(r));
    perf_sql__bind_int64(S->stmt_regs, regname, val);
	}
  CALL_SQLITE_EXPECT(step(S->stmt_regs),DONE,S->db);
  CALL_SQLITE(reset(S->stmt_regs),S->db);
  CALL_SQLITE(clear_bindings(S->stmt_regs),S->db);
  rowid = sqlite3_last_insert_rowid(S->db);
  CALL_SQLITE(bind_int64(stmt_sample, idx, rowid),S->db);
}

static sqlite3_int64 perf_sql__insert_branch_addr(struct perf_sql *S,
                      struct thread *thread, u8 cpumode, u64 addr)
{
  sqlite3_int64 rowid = 0;
	struct addr_location al;
  char *ipstr = NULL;
	memset(&al, 0, sizeof(al));

  thread__find_addr_map(thread, cpumode, MAP__FUNCTION, addr, &al);

  ipstr = sqlite3_mprintf("%" PRIx64, addr);
  BIND_INSERT_AND_SELECT(text_transient, S->stmt_ip, "@ip", ipstr);
  sqlite3_free(ipstr);

  if (al.map)
    al.sym = map__find_symbol(al.map, al.addr, NULL);
  perf_sql__bind_symname_offs(S, al.sym, &al);
  perf_sql__bind_dsoname(S, al.map);
  perf_sql__bind_srcline(S, al.map, al.addr);
  CALL_SQLITE_EXPECT(step(S->stmt_ip),DONE,S->db);
  CALL_SQLITE(reset(S->stmt_ip),S->db);
  CALL_SQLITE(clear_bindings(S->stmt_ip),S->db);

  CALL_SQLITE_EXPECT(step(S->stmt_ip_sel),ROW,S->db);
  rowid = sqlite3_column_int64(S->stmt_ip_sel, 0);
  CALL_SQLITE(reset(S->stmt_ip_sel),S->db);
  CALL_SQLITE(clear_bindings(S->stmt_ip_sel),S->db);

  return rowid;
}

static inline const char *
mispred_str(struct branch_entry *br)
{
	if (!(br->flags.mispred  || br->flags.predicted))
		return "-";

	return br->flags.predicted ? "P" : "M";
}



  // static int callback(void *NotUsed __maybe_unused, int argc, char **argv, char **azColName)
  // {
  //   int i;
  //   int rowpr=argc-1;
  //   //NotUsed=0;
  //   printf ("\n ******** Inside Callback\n");
  //   //printf("\n %s ",__FUNCTION__);
  //   for(i=0; i<rowpr; i++)
  //     printf("%s ",azColName[i]);

  //   printf("%s\n",azColName[rowpr]);



  //   for(i=0; i<rowpr; i++){
  //     printf("%s ",  argv[i] ? argv[i] : "NULL");

  //   }
  //   printf("%s\n",  argv[rowpr] ? argv[rowpr] : "NULL");

  //   return 0;
  // }


void perf_sql__insert_branch_stack(struct perf_sql *S,
        struct perf_evsel *evsel,
        union perf_event *event __maybe_unused,
			  struct perf_sample *sample,
			  struct thread *thread __maybe_unused,
			  struct perf_event_attr *attr __maybe_unused)
{
  sqlite3_stmt *stmt_sample = perf_sql__get_stmt(S, evsel);
  int idx = sqlite3_bind_parameter_index(stmt_sample, "@brstack");
	struct branch_stack *br = sample->branch_stack;
	u8 cpumode = event->header.misc & PERF_RECORD_MISC_CPUMODE_MASK;
	u64 i, from, to;
  sqlite3_int64 from_id, to_id, rowid;
  const int intlen = 66;
  char rowidstr[intlen];
  char *branchstack_val = NULL;

  //int  ret = 0;

	if (!(br && br->nr))
		return;

  assert(idx);
  //printf("%s\n", sqlite3_sql(stmt_sample));

  branchstack_val = calloc(1, br->nr*intlen);
  branchstack_val[0] = '\0';

	for (i = 0; i < br->nr; i++) {
		from = br->entries[i].from;
		to   = br->entries[i].to;

    from_id = perf_sql__insert_branch_addr(S, thread, cpumode, from);
    to_id = perf_sql__insert_branch_addr(S, thread, cpumode, to);

    BIND_INSERT_AND_SELECT(int64, S->stmt_branch_entry, "@from", from_id);
   // printf("%lld\n",from_id);
    BIND_INSERT_AND_SELECT(int64, S->stmt_branch_entry, "@to", to_id);
   // printf("%lld\n",to_id);
    BIND_INSERT_AND_SELECT(text, S->stmt_branch_entry, "@predicted",
                        mispred_str(br->entries+i));
   // printf("%s\n",  mispred_str(br->entries+i));
    BIND_INSERT_AND_SELECT(text, S->stmt_branch_entry, "@in_tx",
                        br->entries[i].flags.in_tx? "X" : "-");
   // printf("%s\n", br->entries[i].flags.in_tx? "X" : "-");
    BIND_INSERT_AND_SELECT(text, S->stmt_branch_entry, "@abort",
                        br->entries[i].flags.abort? "A" : "-");
   // printf("%s\n", br->entries[i].flags.abort? "A" : "-");
    BIND_INSERT_AND_SELECT(int, S->stmt_branch_entry, "@cycles",
                         br->entries[i].flags.cycles);
                         //10);
   // printf("%d\n",br->entries[i].flags.cycles);

    CALL_SQLITE_EXPECT(step(S->stmt_branch_entry),DONE,S->db);
    CALL_SQLITE(reset(S->stmt_branch_entry),S->db);
    CALL_SQLITE(clear_bindings(S->stmt_branch_entry),S->db);

    //sqlite3_exec(S->db, "select * from branch_entry;",callback,NULL,NULL);
    //sqlite3_exec(S->db,create_table1,callback,handle,&errmsg);

    CALL_SQLITE_EXPECT(step(S->stmt_branch_entry_sel),ROW,S->db);
    rowid = sqlite3_column_int64(S->stmt_branch_entry_sel, 0);
    snprintf(rowidstr, intlen, "%lld/", rowid);
    strcat(branchstack_val, rowidstr);
	  CALL_SQLITE(reset(S->stmt_branch_entry_sel),S->db);
    CALL_SQLITE(clear_bindings(S->stmt_branch_entry_sel),S->db);
  }

  CALL_SQLITE(bind_text(stmt_sample, idx, branchstack_val, -1, SQLITE_TRANSIENT),S->db);
  free(branchstack_val);
}

