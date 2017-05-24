#include "dbcs.h"
#include "sqlite3.h"

/*
defines
*/

#define LOCK_SQLITE()  
#define UNLOCK_SQLITE()  

#define SDB_SQLITE_BUSY_TIMEOUT 1000 /* milliseconds */
#define SDB_BUSY_RETRY_TIME        5 /* seconds */
#define SDB_MAX_BUSY_RETRIES      10


typedef struct SDB {
	sqlite3 *sdb_p;
	char * sdb_path;
}SDB;

/*
vars
*/
static const char BEGIN_CMD[] = "BEGIN IMMEDIATE TRANSACTION;";
static const char COMMIT_CMD[] = "COMMIT TRANSACTION;";
static const char ROLLBACK_CMD[] = "ROLLBACK TRANSACTION;"; 
static const char CHECK_TABLE_CMD[] = "SELECT ALL * FROM %s LIMIT 0;";
static const char *CREATE_TABLE_CMD[] =
{ "CREATE TABLE if not exists table_certificate (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, content, store_type, id_attr);"
, "CREATE TABLE if not exists table_certificate_attr (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, cert_alg_type, cert_use_type, skf_name, device_name, application_ame, container_name, common_name, subject, isuue, public_key, serial_number, vendor_data, subject_keyid, isuue_keyid, verify, not_before, not_after);"
, "CREATE TABLE if not exists table_skf (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name, path);"
, "CREATE TABLE if not exists table_pid_vid (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, pid, vid);"
, "CREATE TABLE if not exists table_product (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name, id_skf, id_pid_vid);"
, "CREATE TABLE if not exists table_check_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, description);"
, "CREATE TABLE if not exists table_check_keyid_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, keyid, type);"
, "CREATE TABLE if not exists table_fix_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type);"
, "CREATE TABLE if not exists table_data (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, data);"
, "CREATE TABLE if not exists table_element (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, data, description);"
, "CREATE TABLE if not exists table_tlv (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, value);"
, "CREATE TABLE if not exists table_path (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name, value);"
};


/*
functions declar
*/

#ifdef __cplusplus
extern "C" {
#endif
	int SMB_DB_Init(char *sdb_path);
#ifdef __cplusplus
}
#endif

/*
function implement
*/

static int sdb_openDB(const char *name, sqlite3 **sqlDB)
{
	int sqlerr = SQLITE_OK;

	int bFlagExist = 0;
	int bFlagUpdate = 0;

	*sqlDB = NULL;
	sqlerr = sqlite3_open(name, sqlDB);
	if (sqlerr != SQLITE_OK) {
		goto err;
	}

	sqlerr = sqlite3_busy_timeout(*sqlDB, SDB_SQLITE_BUSY_TIMEOUT);
	if (sqlerr != SQLITE_OK) {
		sqlite3_close(*sqlDB);
		*sqlDB = NULL;
		return sqlerr;
	}

err:

	return sqlerr;
}

static int sdb_done(int err, int *count)
{
	/* allow as many rows as the database wants to give */
	if (err == SQLITE_ROW) {
		*count = 0;
		return 0;
	}
	if (err != SQLITE_BUSY) {
		return 1;
	}
	/* err == SQLITE_BUSY, Dont' retry forever in this case */
	if (++(*count) >= SDB_MAX_BUSY_RETRIES) {
		return 1;
	}
	return 0;
}

static int sdb_complete(sqlite3 *sdb, const char *cmd)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;

	sqlerr = sqlite3_prepare_v2(sdb, cmd, -1, &stmt, NULL);

	do {
		sqlerr = sqlite3_step(stmt);
		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

	} while (!sdb_done(sqlerr, &retry));

	/* Pending BEGIN TRANSACTIONS Can move forward at this point. */

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
	}

	sqlite3_close(sdb);

	return sqlerr;
}

int sdb_Begin(SDB *sdb)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;

	LOCK_SQLITE();

	/* get a new version that we will use for the entire transaction */
	sqlerr = sdb_openDB(sdb->sdb_path, &sdb->sdb_p);
	if (sqlerr != SQLITE_OK) {
		goto err;
	}

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, BEGIN_CMD, -1, &stmt, NULL);

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

	} while (!sdb_done(sqlerr, &retry));

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
	}

err:


	if (sqlerr == SQLITE_OK) {

	}
	else {
		/* we failed to start our transaction,
		* free any databases we opened. */
		if (sdb->sdb_p) {
			sqlite3_close(sdb->sdb_p);
		}
	}

	UNLOCK_SQLITE();
	return sqlerr;
}

int sdb_Commit(SDB *sdb)
{
	int crv;
	LOCK_SQLITE();
	crv = sdb_complete(sdb->sdb_p, COMMIT_CMD);
	UNLOCK_SQLITE();
	return crv;
}

int sdb_Abort(SDB *sdb)
{
	int crv;
	LOCK_SQLITE();
	crv = sdb_complete(sdb->sdb_p, ROLLBACK_CMD);
	UNLOCK_SQLITE();
	return crv;
}

/* return 1 if sqlDB contains table 'tableName */
static int tableExists(sqlite3 *sqlDB, const char *tableName)
{
	char * cmd = sqlite3_mprintf(CHECK_TABLE_CMD, tableName);
	int sqlerr = SQLITE_OK;

	if (cmd == NULL) {
		return 0;
	}

	sqlerr = sqlite3_exec(sqlDB, cmd, NULL, 0, 0);
	sqlite3_free(cmd);

	return (sqlerr == SQLITE_OK) ? 1 : 0;
}

int sdb_Init(SDB *sdb)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	
	int i = 0;
	LOCK_SQLITE();

	for (i = 0; i < sizeof(CREATE_TABLE_CMD) / sizeof(char *); i++)
	{
		const char *cmd = CREATE_TABLE_CMD[i];
		sqlerr = sqlite3_exec(sdb->sdb_p, cmd, NULL, 0, NULL);
		if (sqlerr != SQLITE_OK)
		{
			goto err;
		}
	}
err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
	}
	UNLOCK_SQLITE();
	return sqlerr;
}

int SMB_DB_Init(char *sdb_path)
{
	int crv = 0;
	SDB sdb = {0};

	sdb.sdb_path = sdb_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_Init(&sdb);
	if (crv)
	{
		goto err;
	}
err:

	if (crv)
	{
		sdb_Abort(&sdb);
	}
	else
	{
		sdb_Commit(&sdb);
	}


	return 0;
}

