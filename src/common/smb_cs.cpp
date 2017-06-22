#include "smb_cs.h"
#include "smb_cs_inner.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <map>

#include "sqlite3.h"
#include "smcert.h"
#include "o_all_func_def.h"
#include "certificate_items_parse.h"
#include "openssl_func_def.h"
#include <math.h>

#if defined(WIN32) || defined(WINDOWS)
#include <Windows.h>
#include <WinCrypt.h>
#else
strcpy(smb_db_path, "/home/");
#endif

std::map<void*, int> g_mapPtr2IDs;

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

char smb_db_path[BUFFER_LEN_1K] = { 0 };

static const char BEGIN_CMD[] = "BEGIN IMMEDIATE TRANSACTION;";
static const char COMMIT_CMD[] = "COMMIT TRANSACTION;";
static const char ROLLBACK_CMD[] = "ROLLBACK TRANSACTION;";
static const char CHECK_TABLE_CMD[] = "SELECT ALL * FROM %s LIMIT 0;";
static const char *CREATE_TABLE_CMD[] =
{ "CREATE TABLE if not exists table_certificate (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, content UNIQUE ON CONFLICT REPLACE, store_type, id_attr);"
, "CREATE TABLE if not exists table_certificate_attr (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid UNIQUE ON CONFLICT REPLACE, isuue_keyid, vendor_data, verify, not_before, not_after);"
, "CREATE TABLE if not exists table_skf (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name, path UNIQUE ON CONFLICT REPLACE, signtype, pin_verify);"
, "CREATE TABLE if not exists table_pid_vid (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, pid UNIQUE ON CONFLICT REPLACE, vid, type);"
, "CREATE TABLE if not exists table_product (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name UNIQUE ON CONFLICT REPLACE, id_skf, id_pid_vid);"
, "CREATE TABLE if not exists table_check_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type UNIQUE ON CONFLICT REPLACE, description);"
, "CREATE TABLE if not exists table_check_keyid_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, keyid UNIQUE ON CONFLICT REPLACE, type);"
, "CREATE TABLE if not exists table_fix_list (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type UNIQUE ON CONFLICT REPLACE);"
, "CREATE TABLE if not exists table_data (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, data);"
, "CREATE TABLE if not exists table_element (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, data, description);"
, "CREATE TABLE if not exists table_tlv (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, type, value);"
, "CREATE TABLE if not exists table_path (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name UNIQUE ON CONFLICT REPLACE, value, digest_md5, digest_sha1);"
, "CREATE TABLE if not exists table_csp (id INTEGER PRIMARY KEY UNIQUE ON CONFLICT REPLACE, name UNIQUE ON CONFLICT REPLACE, value);"
};


/*
functions declar
*/

#ifdef __cplusplus
extern "C" {
#endif

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
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

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

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}
err:

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
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
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

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

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

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
		stmt = NULL;
	}
	UNLOCK_SQLITE();
	return sqlerr;
}



unsigned int SMB_DB_Init()
{
	int crv = 0;
	SDB sdb = { 0 };

	SMB_DB_Path_Init(NULL);

	sdb.sdb_path = smb_db_path;

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


	return crv;
}

int sdb_EnumSKF(SDB *sdb, char * pszSKFNames, unsigned int * puiSKFNamesLen)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;
	char data_value[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len_real = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_skf;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			memcpy(data_value + data_len_real, (char *)sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));

			data_len_real += sqlite3_column_bytes(stmt, 1);

			data_value[data_len_real] = '\0';
			data_len_real += 1;
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{
		if (NULL == pszSKFNames)
		{
			*puiSKFNamesLen = data_len_real;
			sqlerr = 0;
		}
		else if (*puiSKFNamesLen < data_len_real)
		{
			*puiSKFNamesLen = data_len_real;
			sqlerr = EErr_SMB_MEM_LES;
		}
		else
		{
			*puiSKFNamesLen = data_len_real;
			memcpy(pszSKFNames, data_value, data_len_real);
			sqlerr = 0;
		}
	}

	return sqlerr;
}

unsigned int SMB_CS_CreateCtx(SMB_CS_CertificateContext **ppCertCtx, unsigned char *pCertificate, unsigned int uiCertificateLen)
{
	SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));
	unsigned int uiRet = -1;

	if (!pCertCtx)
	{
		uiRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));

	pCertCtx->stContent.length = uiCertificateLen;
	pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
	memcpy(pCertCtx->stContent.data, pCertificate, pCertCtx->stContent.length);

	uiRet = SMB_CS_FillCertAttr(pCertCtx);
	if (0 != uiRet)
	{
		goto err;
	}
	*ppCertCtx = pCertCtx;
err:

	return uiRet;
}

unsigned int SMB_CS_FillCertAttr(SMB_CS_CertificateContext * pCertCtx)
{
	unsigned int ulRet = 0;
	if (NULL == pCertCtx)
	{
		goto err;
	}
	else
	{
		{
			CertificateItemParse certParse;

			if (0 != certParse.setCertificate(pCertCtx->stContent.data, pCertCtx->stContent.length))
			{
				ulRet = EErr_SMB_INVALID_ARG;
				goto err;
			}

			certParse.parse();

			pCertCtx->stAttr.ucCertAlgType = certParse.m_iKeyAlg;

			if (pCertCtx->stAttr.stSubjectKeyID.data)
			{
				free(pCertCtx->stAttr.stSubjectKeyID.data);
				pCertCtx->stAttr.stSubjectKeyID.data = NULL;
			}
			pCertCtx->stAttr.stSubjectKeyID.length = certParse.m_strSubjectKeyID.size();
			pCertCtx->stAttr.stSubjectKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubjectKeyID.length);
			memcpy(pCertCtx->stAttr.stSubjectKeyID.data, certParse.m_strSubjectKeyID.c_str(), pCertCtx->stAttr.stSubjectKeyID.length);

			if (pCertCtx->stAttr.stIssueKeyID.data)
			{
				free(pCertCtx->stAttr.stIssueKeyID.data);
				pCertCtx->stAttr.stIssueKeyID.data = NULL;
			}
			pCertCtx->stAttr.stIssueKeyID.length = certParse.m_strIssueKeyID.size();
			pCertCtx->stAttr.stIssueKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssueKeyID.length);
			memcpy(pCertCtx->stAttr.stIssueKeyID.data, certParse.m_strIssueKeyID.c_str(), pCertCtx->stAttr.stIssueKeyID.length);
		}

		// 证书的属性
		char data_info_value[1024] = { 0 };
		int data_info_len = 0;

		WT_SetMyCert(pCertCtx->stContent.data, pCertCtx->stContent.length);

		memset(data_info_value, 0, 1024);
		WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
		if (pCertCtx->stAttr.stSerialNumber.data)
		{
			free(pCertCtx->stAttr.stSerialNumber.data);
			pCertCtx->stAttr.stSerialNumber.data = NULL;
		}
		pCertCtx->stAttr.stSerialNumber.length = strlen(data_info_value) + 1;
		pCertCtx->stAttr.stSerialNumber.data = (unsigned char *)malloc(pCertCtx->stAttr.stSerialNumber.length);
		memcpy(pCertCtx->stAttr.stSerialNumber.data, data_info_value, pCertCtx->stAttr.stSerialNumber.length);

		memset(data_info_value, 0, 1024);
		WT_GetCertInfo(CERT_ISSUER_DN, -1, data_info_value, &data_info_len);
		if (pCertCtx->stAttr.stIssue.data)
		{
			free(pCertCtx->stAttr.stIssue.data);
			pCertCtx->stAttr.stIssue.data = NULL;
		}
		pCertCtx->stAttr.stIssue.length = strlen(data_info_value) + 1;
		pCertCtx->stAttr.stIssue.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssue.length);
		memcpy(pCertCtx->stAttr.stIssue.data, data_info_value, pCertCtx->stAttr.stIssue.length);

		memset(data_info_value, 0, 1024);
		WT_GetCertInfo(CERT_SUBJECT_DN, -1, data_info_value, &data_info_len);
		if (pCertCtx->stAttr.stSubject.data)
		{
			free(pCertCtx->stAttr.stSubject.data);
			pCertCtx->stAttr.stSubject.data = NULL;
		}
		pCertCtx->stAttr.stSubject.length = strlen(data_info_value) + 1;
		pCertCtx->stAttr.stSubject.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubject.length);
		memcpy(pCertCtx->stAttr.stSubject.data, data_info_value, pCertCtx->stAttr.stSubject.length);

		memset(data_info_value, 0, 1024);
		WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
		if (pCertCtx->stAttr.stCommonName.data)
		{
			free(pCertCtx->stAttr.stCommonName.data);
			pCertCtx->stAttr.stCommonName.data = NULL;
		}
		pCertCtx->stAttr.stCommonName.length = strlen(data_info_value) + 1;
		pCertCtx->stAttr.stCommonName.data = (unsigned char *)malloc(pCertCtx->stAttr.stCommonName.length);
		memcpy(pCertCtx->stAttr.stCommonName.data, data_info_value, pCertCtx->stAttr.stCommonName.length);

		WT_ClearCert();


	}

err:

	return ulRet;

}

int sdb_FillCtx(SMB_CS_CertificateContext **ppCertCtx, SMB_CS_CertificateFindAttr *pCertificateFindAttr, sqlite3_stmt *stmt)
{
	SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));

	memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));


	//id content, store_type, id_attr,
	//cert_alg_type, cert_usage_type, skf_name, device_name, application_name, 
	//container_name, common_name, subject, isuue, public_key, serial_number, 
	//subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after

	int pos = -1;

	pos += 1;

	g_mapPtr2IDs[&pCertCtx->stContent] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stContent.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
	memcpy(pCertCtx->stContent.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stContent.length);

	pos += 1;
	pCertCtx->ucStoreType = sqlite3_column_int(stmt, pos);

	pos += 1;
	g_mapPtr2IDs[&pCertCtx->stAttr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stAttr.ucCertAlgType = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stAttr.ucCertUsageType = sqlite3_column_int(stmt, pos);

	pos += 1;
	pCertCtx->stAttr.stSKFName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSKFName.data = (unsigned char *)malloc(pCertCtx->stAttr.stSKFName.length);
	memcpy(pCertCtx->stAttr.stSKFName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSKFName.length);

	pos += 1;
	pCertCtx->stAttr.stDeviceName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stDeviceName.data = (unsigned char *)malloc(pCertCtx->stAttr.stDeviceName.length);
	memcpy(pCertCtx->stAttr.stDeviceName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stDeviceName.length);

	pos += 1;
	pCertCtx->stAttr.stApplicationName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stApplicationName.data = (unsigned char *)malloc(pCertCtx->stAttr.stApplicationName.length);
	memcpy(pCertCtx->stAttr.stApplicationName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stApplicationName.length);

	pos += 1;
	pCertCtx->stAttr.stContainerName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stContainerName.data = (unsigned char *)malloc(pCertCtx->stAttr.stContainerName.length);
	memcpy(pCertCtx->stAttr.stContainerName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stContainerName.length);

	pos += 1;
	pCertCtx->stAttr.stCommonName.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stCommonName.data = (unsigned char *)malloc(pCertCtx->stAttr.stCommonName.length);
	memcpy(pCertCtx->stAttr.stCommonName.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stCommonName.length);

	pos += 1;
	pCertCtx->stAttr.stSubject.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSubject.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubject.length);
	memcpy(pCertCtx->stAttr.stSubject.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSubject.length);

	pos += 1;
	pCertCtx->stAttr.stIssue.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stIssue.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssue.length);
	memcpy(pCertCtx->stAttr.stIssue.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stIssue.length);

	pos += 1;
	pCertCtx->stAttr.stPublicKey.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stPublicKey.data = (unsigned char *)malloc(pCertCtx->stAttr.stPublicKey.length);
	memcpy(pCertCtx->stAttr.stPublicKey.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stPublicKey.length);

	pos += 1;
	pCertCtx->stAttr.stSerialNumber.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSerialNumber.data = (unsigned char *)malloc(pCertCtx->stAttr.stSerialNumber.length);
	memcpy(pCertCtx->stAttr.stSerialNumber.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSerialNumber.length);

	pos += 1;
	pCertCtx->stAttr.stSubjectKeyID.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stSubjectKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stSubjectKeyID.length);
	memcpy(pCertCtx->stAttr.stSubjectKeyID.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stSubjectKeyID.length);

	pos += 1;
	pCertCtx->stAttr.stIssueKeyID.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stIssueKeyID.data = (unsigned char *)malloc(pCertCtx->stAttr.stIssueKeyID.length);
	memcpy(pCertCtx->stAttr.stIssueKeyID.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stIssueKeyID.length);

	pos += 1;
	pCertCtx->stAttr.stVendorData.length = sqlite3_column_bytes(stmt, pos);
	pCertCtx->stAttr.stVendorData.data = (unsigned char *)malloc(pCertCtx->stAttr.stVendorData.length);
	memcpy(pCertCtx->stAttr.stVendorData.data, (char *)sqlite3_column_blob(stmt, pos), pCertCtx->stAttr.stVendorData.length);


	pos += 1;
	pCertCtx->stAttr.ulVerify = sqlite3_column_int(stmt, pos);


	pos += 1;
	pCertCtx->stAttr.ulNotBefore = sqlite3_column_int64(stmt, pos);


	pos += 1;
	pCertCtx->stAttr.ulNotAfter = sqlite3_column_int64(stmt, pos);


	if (NULL == pCertificateFindAttr)
	{
		*ppCertCtx = pCertCtx;
	}
	else
	{
		bool bExist = true;

		if ((pCertificateFindAttr->uiFindFlag & 1) && pCertCtx->stAttr.ucCertAlgType != pCertificateFindAttr->ucCertAlgType)
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 2) && pCertCtx->stAttr.ucCertUsageType != pCertificateFindAttr->ucCertUsageType)
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 4) && pCertCtx->ucStoreType != pCertificateFindAttr->ucStoreType)
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 8) && 0 != memcmp(pCertCtx->stAttr.stSubject.data, pCertificateFindAttr->stSubject.data, pCertificateFindAttr->stSubject.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 16) && 0 != memcmp(pCertCtx->stAttr.stIssue.data, pCertificateFindAttr->stIssue.data, pCertificateFindAttr->stIssue.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 32) && 0 != memcmp(pCertCtx->stAttr.stPublicKey.data, pCertificateFindAttr->stPublicKey.data, pCertificateFindAttr->stPublicKey.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 64) && 0 != memcmp(pCertCtx->stAttr.stSerialNumber.data, pCertificateFindAttr->stSerialNumber.data, pCertificateFindAttr->stSerialNumber.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 128) && 0 != memcmp(pCertCtx->stAttr.stSubjectKeyID.data, pCertificateFindAttr->stSubjectKeyID.data, pCertificateFindAttr->stSubjectKeyID.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 256) && 0 != memcmp(pCertCtx->stAttr.stIssueKeyID.data, pCertificateFindAttr->stIssueKeyID.data, pCertificateFindAttr->stIssueKeyID.length))
		{
			bExist = false;
		}
		if ((pCertificateFindAttr->uiFindFlag & 512) && 0 != memcmp(pCertCtx->stAttr.stVendorData.data, pCertificateFindAttr->stVendorData.data, pCertificateFindAttr->stVendorData.length))
		{
			bExist = false;
		}

		if (bExist)
		{
			*ppCertCtx = pCertCtx;
		}
		else
		{
			SMB_CS_FreeCtx(pCertCtx);
			*ppCertCtx = NULL;
		}
	}

	return 0;
}

int sdb_FindCtx(SDB *sdb, SMB_CS_CertificateFindAttr *pCertificateFindAttr, SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select a.id as id, content, store_type, id_attr, "
		"cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after "
		"from table_certificate as a,table_certificate_attr as b where a.id_attr=b.id; ", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_CertificateContext *pCertCtx = NULL;
			sdb_FillCtx(&pCertCtx, pCertificateFindAttr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppCertCtxNodeHeader, (void *)pCertCtx);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_FindCtx(SMB_CS_CertificateFindAttr *pCertificateFindAttr, SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_FindCtx(&sdb, pCertificateFindAttr, ppCertCtxNodeHeader);
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

	return crv;
}



unsigned int SMB_CS_SetCtxVendor(SMB_CS_CertificateContext *pCertCtx, unsigned char *pVendor, unsigned int uiVendorLen)
{
	unsigned int ulRet = 0;
	if (NULL == pCertCtx)
	{
		goto err;
	}
	else
	{
		if (pCertCtx->stAttr.stVendorData.data)
		{
			free(pCertCtx->stAttr.stVendorData.data);
			pCertCtx->stAttr.stVendorData.data = NULL;
		}

		pCertCtx->stAttr.stVendorData.length = uiVendorLen;
		pCertCtx->stAttr.stVendorData.data = (unsigned char *)malloc(pCertCtx->stAttr.stVendorData.length);
		memcpy(pCertCtx->stAttr.stVendorData.data, pVendor, pCertCtx->stAttr.stVendorData.length);
	}
err:
	return ulRet;
}

unsigned int SMB_CS_FreeCtx(SMB_CS_CertificateContext *pCertCtx)
{
	if (pCertCtx)
	{
		if (pCertCtx->stContent.data)
		{
			free(pCertCtx->stContent.data);
			pCertCtx->stContent.data = NULL;
		}

		if (pCertCtx->stAttr.stSKFName.data)
		{
			free(pCertCtx->stAttr.stSKFName.data);
			pCertCtx->stAttr.stSKFName.data = NULL;
		}

		if (pCertCtx->stAttr.stDeviceName.data)
		{
			free(pCertCtx->stAttr.stDeviceName.data);
			pCertCtx->stAttr.stDeviceName.data = NULL;
		}

		if (pCertCtx->stAttr.stApplicationName.data)
		{
			free(pCertCtx->stAttr.stApplicationName.data);
			pCertCtx->stAttr.stApplicationName.data = NULL;
		}

		if (pCertCtx->stAttr.stContainerName.data)
		{
			free(pCertCtx->stAttr.stContainerName.data);
			pCertCtx->stAttr.stContainerName.data = NULL;
		}

		if (pCertCtx->stAttr.stCommonName.data)
		{
			free(pCertCtx->stAttr.stCommonName.data);
			pCertCtx->stAttr.stCommonName.data = NULL;
		}

		if (pCertCtx->stAttr.stSubject.data)
		{
			free(pCertCtx->stAttr.stSubject.data);
			pCertCtx->stAttr.stSubject.data = NULL;
		}

		if (pCertCtx->stAttr.stIssue.data)
		{
			free(pCertCtx->stAttr.stIssue.data);
			pCertCtx->stAttr.stIssue.data = NULL;
		}

		if (pCertCtx->stAttr.stPublicKey.data)
		{
			free(pCertCtx->stAttr.stPublicKey.data);
			pCertCtx->stAttr.stPublicKey.data = NULL;
		}

		if (pCertCtx->stAttr.stSerialNumber.data)
		{
			free(pCertCtx->stAttr.stSerialNumber.data);
			pCertCtx->stAttr.stSerialNumber.data = NULL;
		}

		if (pCertCtx->stAttr.stSubjectKeyID.data)
		{
			free(pCertCtx->stAttr.stSubjectKeyID.data);
			pCertCtx->stAttr.stSubjectKeyID.data = NULL;
		}

		if (pCertCtx->stAttr.stIssueKeyID.data)
		{
			free(pCertCtx->stAttr.stIssueKeyID.data);
			pCertCtx->stAttr.stIssueKeyID.data = NULL;
		}

		if (pCertCtx->stAttr.stVendorData.data)
		{
			free(pCertCtx->stAttr.stVendorData.data);
			pCertCtx->stAttr.stVendorData.data = NULL;
		}

		free(pCertCtx);
		pCertCtx = NULL;
	}

	return 0;
}

unsigned int SMB_CS_FreeCtxLink(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader)
{
	while (*ppCertCtxNodeHeader)
	{
		SMB_CS_FreeCtx((*ppCertCtxNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppCertCtxNodeHeader, (*ppCertCtxNodeHeader)->ptr_data);
	}

	return 0;
}

unsigned int sdb_GetCtxByCert(SDB *sdb, SMB_CS_CertificateContext **ppCertCtx, unsigned char *pCertificate, unsigned int uiCertificateLen)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select a.id as id content, store_type, id_attr, "
		"cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after "
		"from table_certificate as a,table_certificate as b where a.id_attr=b.id and content=$content limit(0,1); ", -1, &stmt, NULL);

	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	sqlerr = sqlite3_bind_blob(stmt, 1, pCertificate, uiCertificateLen, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_CertificateContext *pCertCtx = NULL;
			sdb_FillCtx(&pCertCtx, NULL, stmt);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_GetCtxByCert(SMB_CS_CertificateContext **ppCertCtx, unsigned char *pCertificate, unsigned int uiCertificateLen)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_GetCtxByCert(&sdb, ppCertCtx, pCertificate, uiCertificateLen);
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

	return crv;
}


unsigned int SMB_CS_VerifyCert(unsigned int uiFlag, unsigned char* pbCert, unsigned int uiCertLen)
{
	unsigned int ulRet = 0;

	unsigned int ulAlgType = 0;

	CertificateItemParse certParse;

	SMB_CS_CertificateContext *ctx = NULL;

	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;

#if defined(WIN32) || defined(WINDOWS)
	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = { 0 };
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;
#endif

	if (0 != certParse.setCertificate(pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	certParse.parse();

	ulAlgType = certParse.m_iKeyAlg;

	if (CERT_ALG_RSA_FLAG == ulAlgType)
	{
#if defined(WIN32) || defined(WINDOWS)
		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}
		// TIME
		if (CERT_VERIFY_TIME_FLAG & uiFlag)
		{
			ulRet = CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
			if (ulRet)
			{
				ulRet = EErr_SMB_VERIFY_TIME;
				goto err;
			}
		}
		// SIGN CERT
		if (CERT_VERIFY_CHAIN_FLAG & uiFlag)
		{
			// 打开存储区		
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
												 // not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
												 // registry location
				L"Ca"                            // The store name as a Unicode 
												 // string
			);

			if (NULL == hCertStore)
			{
				ulRet = EErr_SMB_OPEN_STORE;
				goto err;
			}

			// 查找颁发者证书
			certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);

			if (NULL == certContext_OUT)
			{
				if (hCertStore)
				{
					// 关闭存储区
					CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
				}

				// 打开存储区		
				hCertStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM,          // The store provider type
					0,                               // The encoding type is
													 // not needed
					NULL,                            // Use the default HCRYPTPROV
					CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													 // registry location
					L"Root"                            // The store name as a Unicode 
													   // string
				);

				if (NULL == hCertStore)
				{
					ulRet = EErr_SMB_OPEN_STORE;
					goto err;
				}

				// 查找颁发者证书
				certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
			}

			if (NULL != certContext_OUT)
			{
				DWORD  dwFlags = CERT_STORE_SIGNATURE_FLAG;

				// 验证颁发者证书
				if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, uiCertLen))
				{

				}
				else
				{
					// 验证上级证书
					ulRet = SMB_CS_VerifyCert(uiFlag, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);
					if (ulRet)
					{
						goto err;
					}
				}

				if (!CertVerifySubjectCertificateContext(certContext_IN, certContext_OUT, &dwFlags))
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}

				if (dwFlags)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
				}
			}
			else
			{
				ulRet = EErr_SMB_NO_CERT_CHAIN;
				goto err;
			}
		}
		//CRL
		if (CERT_VERIFY_CRL_FLAG & uiFlag)
		{

		}
#else
		ulRet = OpenSSL_VerifyCertChain(pbCert, uiCertLen);
#endif
		goto err;
	}


	// 创建上下文 
	SMB_CS_CreateCtx(&ctx, pbCert, uiCertLen);

	if (!ctx)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}
	// TIME
	if (CERT_VERIFY_TIME_FLAG & uiFlag)
	{
		time_t time_now;
		time(&time_now);

		if (time_now > certParse.m_tNotAfter || time_now < certParse.m_tNotBefore)
		{
			ulRet = EErr_SMB_VERIFY_TIME;
			goto err;
		}
	}
	// SIGN CERT
	if (CERT_VERIFY_CHAIN_FLAG & uiFlag)
	{
		// 查找颁发者证书
		SMB_CS_CertificateFindAttr findAttr = { 0 };

		findAttr.uiFindFlag = 128;

		findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
		findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

		SMB_CS_FindCtx(&findAttr, &ctxHeader);

		if (NULL != ctxHeader)
		{
			// 验证颁发者证书
			if (0 == memcmp(ctxHeader->ptr_data->stContent.data, pbCert, uiCertLen))
			{

			}
			else
			{
				// 验证上级证书
				ulRet = SMB_CS_VerifyCert(uiFlag, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					goto err;
				}
			}
			switch (ulAlgType)
			{
			case CERT_ALG_RSA_FLAG:
			{
				ulRet = OpenSSL_VerifyCert(pbCert, uiCertLen, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}
				break;
			}
			case CERT_ALG_SM2_FLAG:
			{
				OpenSSL_Initialize();

				ulRet = OpenSSL_VerifyCert(pbCert, uiCertLen, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
				if (ulRet)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}
				break;
			}
			default:
				break;
			}
		}
		else
		{
			ulRet = EErr_SMB_NO_CERT_CHAIN;
			goto err;
		}
	}
	//CRL
	if (CERT_VERIFY_CRL_FLAG & uiFlag)
	{

	}
err:

	if (NULL != ctx)
	{
		SMB_CS_FreeCtx(ctx);
	}

	if (NULL != ctxHeader)
	{
		SMB_CS_FreeCtxLink(&ctxHeader);
	}
#if defined(WIN32) || defined(WINDOWS)
	// 释放上下文
	if (certContext_OUT)
	{
		CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if (certContext_IN)
	{
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}

unsigned int SMB_CS_EnumCtx(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned char ucStoreType)
{
	SMB_CS_CertificateFindAttr findAttr;
	if (0 == ucStoreType)
	{
		findAttr.ucStoreType = 0;
		findAttr.uiFindFlag = 0;
	}
	else
	{
		findAttr.ucStoreType = ucStoreType;

		findAttr.uiFindFlag = 4;
	}


	return SMB_CS_FindCtx(&findAttr, ppCertCtxNodeHeader);
}

unsigned int SMB_CS_DelCtxLink(SMB_CS_CertificateContext_NODE *pCertCtxNodeHeader)
{
	while (pCertCtxNodeHeader)
	{
		SMB_CS_DelCtx(pCertCtxNodeHeader->ptr_data);
		pCertCtxNodeHeader = pCertCtxNodeHeader->ptr_next;
	}

	return 0;
}

int sdb_AddCtxToDB(SDB *sdb, SMB_CS_CertificateContext *pCertCtx, unsigned char ucStoreType)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;
	int id_attr = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "INSERT INTO "
		"table_certificate_attr(cert_alg_type, cert_usage_type, skf_name, device_name, application_name, container_name, common_name, subject, isuue, public_key, serial_number, subject_keyid, isuue_keyid, vendor_data, verify, not_before, not_after) "
		"VALUES($cert_alg_type, $cert_usage_type, $skf_name, $device_name, $application_name, $container_name, $common_name, $subject, $isuue, $public_key, $serial_number, $subject_keyid, $isuue_keyid, $vendor_data, $verify, $not_before, $not_after);", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	// $cert_alg_type, 
	sqlerr = sqlite3_bind_int(stmt, 1, pCertCtx->stAttr.ucCertAlgType);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$cert_usage_type, 
	sqlerr = sqlite3_bind_int(stmt, 2, pCertCtx->stAttr.ucCertUsageType);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$skf_name, 
	sqlerr = sqlite3_bind_blob(stmt, 3, pCertCtx->stAttr.stSKFName.data,
		pCertCtx->stAttr.stSKFName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$device_name, 
	sqlerr = sqlite3_bind_blob(stmt, 4, pCertCtx->stAttr.stDeviceName.data,
		pCertCtx->stAttr.stDeviceName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$application_name, 
	sqlerr = sqlite3_bind_blob(stmt, 5, pCertCtx->stAttr.stApplicationName.data,
		pCertCtx->stAttr.stApplicationName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$container_name, 
	sqlerr = sqlite3_bind_blob(stmt, 6, pCertCtx->stAttr.stContainerName.data,
		pCertCtx->stAttr.stContainerName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$common_name, 
	sqlerr = sqlite3_bind_blob(stmt, 7, pCertCtx->stAttr.stCommonName.data,
		pCertCtx->stAttr.stCommonName.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$subject, 
	sqlerr = sqlite3_bind_blob(stmt, 8, pCertCtx->stAttr.stSubject.data,
		pCertCtx->stAttr.stSubject.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$isuue, 
	sqlerr = sqlite3_bind_blob(stmt, 9, pCertCtx->stAttr.stIssue.data,
		pCertCtx->stAttr.stIssue.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$public_key, 
	sqlerr = sqlite3_bind_blob(stmt, 10, pCertCtx->stAttr.stPublicKey.data,
		pCertCtx->stAttr.stPublicKey.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$serial_number, 
	sqlerr = sqlite3_bind_blob(stmt, 11, pCertCtx->stAttr.stSerialNumber.data,
		pCertCtx->stAttr.stSerialNumber.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$subject_keyid, 
	sqlerr = sqlite3_bind_blob(stmt, 12, pCertCtx->stAttr.stSubjectKeyID.data,
		pCertCtx->stAttr.stSubjectKeyID.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$isuue_keyid, 
	sqlerr = sqlite3_bind_blob(stmt, 13, pCertCtx->stAttr.stIssueKeyID.data,
		pCertCtx->stAttr.stIssueKeyID.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$vendor_data,
	sqlerr = sqlite3_bind_blob(stmt, 14, pCertCtx->stAttr.stVendorData.data,
		pCertCtx->stAttr.stVendorData.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$verify, 
	sqlerr = sqlite3_bind_int64(stmt, 15, pCertCtx->stAttr.ulVerify);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$not_before, 
	sqlerr = sqlite3_bind_int64(stmt, 16, pCertCtx->stAttr.ulNotBefore);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$not_after
	sqlerr = sqlite3_bind_int64(stmt, 17, pCertCtx->stAttr.ulNotAfter);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select max(id) from table_certificate_attr;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			id_attr = sqlite3_column_int(stmt, 0);
		}

	} while (!sdb_done(sqlerr, &retry));
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "INSERT INTO "
		"table_certificate (content, store_type, id_attr) "
		"values ($content, $store_type, $id_attr);", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$content
	sqlerr = sqlite3_bind_blob(stmt, 1, pCertCtx->stContent.data, pCertCtx->stContent.length, SQLITE_STATIC);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$store_type
	sqlerr = sqlite3_bind_int(stmt, 2, ucStoreType);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}
	//$id_attr
	sqlerr = sqlite3_bind_int(stmt, 3, id_attr);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_AddCtx(SMB_CS_CertificateContext *pCertCtx, unsigned char ucStoreType)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	SMB_CS_CertificateContext *pCertCtxTmp = NULL;

	SMB_CS_GetCtxByCert(&pCertCtxTmp, pCertCtx->stContent.data, pCertCtx->stContent.length);

	if (pCertCtxTmp)
	{
		SMB_CS_FreeCtx(pCertCtxTmp);
		pCertCtxTmp = NULL;

		return 0;
	}


	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_AddCtxToDB(&sdb, pCertCtx, ucStoreType);
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

	return crv;
}

int sdb_DelCtx(SDB *sdb, SMB_CS_CertificateContext *pCertCtx)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;
	char data_value[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len = BUFFER_LEN_1K;

	LOCK_SQLITE();

	sprintf(data_value, "delete from table_certificate_attr where id=%d", g_mapPtr2IDs[&pCertCtx->stAttr]);
	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, data_value, -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	sprintf(data_value, "delete from table_certificate where id=%d", g_mapPtr2IDs[&pCertCtx->stContent]);
	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, data_value, -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{

		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_DelCtx(SMB_CS_CertificateContext *pCertCtx)
{
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_DelCtx(&sdb, pCertCtx);
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

	return crv;
}

unsigned int SMB_CS_ClrAllCtx(unsigned char ucStoreType)
{
	SMB_CS_CertificateContext_NODE *header = NULL;

	if (ucStoreType > 0)
	{
		SMB_CS_EnumCtx(&header, ucStoreType);

		SMB_CS_DelCtxLink(header);

		SMB_CS_FreeCtxLink(&header);
	}
	else
	{
		for (int i = 0; i < 4; i++)
		{
			SMB_CS_EnumCtx(&header, i + 1);

			SMB_CS_DelCtxLink(header);

			SMB_CS_FreeCtxLink(&header);
		}
	}

	return 0;
}

unsigned int SMB_DB_Path_Init(char *pDbPath)
{
	if (NULL == pDbPath)
	{
		char data_value_zero[BUFFER_LEN_1K] = { 0 };
		char smb_db_path_prefix[BUFFER_LEN_1K] = { 0 };

		int i = 0;

		if (0 == memcmp(data_value_zero, smb_db_path, sizeof(data_value_zero)))
		{
#if defined(WIN32) || defined(WINDOWS)
			//无权限
			GetModuleFileNameA(NULL, smb_db_path_prefix, 1024);
			for (i = strlen(smb_db_path_prefix); i > 0; i--)
			{
				if ('\\' == smb_db_path_prefix[i])
				{
					break;
				}
			}

			GetEnvironmentVariableA("APPDATA", smb_db_path, MAX_PATH);
			strcat(smb_db_path, &smb_db_path_prefix[i]);

			for (i = strlen(smb_db_path); i > 0; i--)
			{
				if ('.' == smb_db_path[i])
				{
					smb_db_path[i] = 0;
					break;
				}
			}

			strcat(smb_db_path, ".smb_cs.db");

			//strcpy(smb_db_path + strlen(smb_db_path), "smb_cs.db");
#else
			strcpy(smb_db_path, "/home/smb_cs.db");
#endif
		}
	}
	else
	{
		strcpy(smb_db_path, pDbPath);
	}

	return 0;
}



unsigned int  SMB_CS_ImportCaCert(unsigned char *pbCert, unsigned int uiCertLen, unsigned int *pulAlgType)
{
	unsigned int ulRet = 0;

	SMB_CS_CertificateContext * ctx = NULL;

#if defined(WIN32) || defined(WINDOWS)
	PCCERT_CONTEXT certContext_IN = NULL;
	HCERTSTORE hCertStore = NULL;
#endif

	SMB_DB_Init();

	if (0 != SMB_CS_CreateCtx(&ctx, pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}
#if defined(WIN32) || defined(WINDOWS)
	if (CERT_ALG_RSA_FLAG == ctx->stAttr.ucCertAlgType)
	{
		if (0 == memcmp(ctx->stAttr.stIssueKeyID.data, ctx->stAttr.stSubjectKeyID.data, ctx->stAttr.stSubjectKeyID.length > ctx->stAttr.stIssueKeyID.length ? ctx->stAttr.stSubjectKeyID.length : ctx->stAttr.stIssueKeyID.length))
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
													// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													// registry location
				L"Root"                            // The store name as a Unicode 
													// string
			);
		}
		else
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
													// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													// registry location
				L"Ca"                            // The store name as a Unicode 
													// string
			);
		}

		if (NULL == hCertStore)
		{
			ulRet = EErr_SMB_OPEN_STORE;
			goto err;
		}

		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE *)pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}

		if (!CertAddCertificateContextToStore(hCertStore, certContext_IN, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
		{
			if (0x80070005 == GetLastError())
			{
				ulRet = EErr_SMB_NO_RIGHT;
			}
			else
			{
				ulRet = EErr_SMB_ADD_CERT_TO_STORE;
			}

			goto err;
		}
		else
		{
			ulRet = EErr_SMB_OK; // success
		}
	}
	else
	{
		if (0 != SMB_CS_AddCtx(ctx, 1))
		{
			ulRet = EErr_SMB_ADD_CERT_TO_STORE;
			goto err;
		}
	}
#else
	if (0 != SMB_CS_AddCtx(ctx, 1))
	{
		ulRet = EErr_SMB_ADD_CERT_TO_STORE;
		goto err;
	}
#endif

	ulRet = EErr_SMB_OK; // success

err:
	if (ctx)
	{
		SMB_CS_FreeCtx(ctx);
	}
#if defined(WIN32) || defined(WINDOWS)
	if (certContext_IN)
	{
		// 释放上下文
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}


int sdb_ExecSQL(SDB *sdb, char *pSqlData, unsigned int uiSqlDataLen)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int pos = 0;
	char data_value[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len_real = 0;
	char * ptr_n = NULL;
	char * ptr_r = NULL;
	char * ptr_semicolon = NULL;

	LOCK_SQLITE();

	for (pos = 0; pos < uiSqlDataLen;)
	{
		while (pSqlData[pos] == '#' || pSqlData[pos] == '\r' || pSqlData[pos] == '\n')
		{
			ptr_n = strstr(&pSqlData[pos], "\n");
			ptr_r = strstr(&pSqlData[pos], "\r");
			if (NULL == ptr_n && NULL == ptr_r)
			{
				pos = uiSqlDataLen;
				break;
			}
			else if (NULL == ptr_n)
			{
				pos = ptr_r - pSqlData + 1;
			}
			else if (NULL == ptr_r)
			{
				pos = ptr_n - pSqlData + 1;
			}
			else
			{
				if (ptr_n > ptr_r)
				{
					pos = ptr_r - pSqlData + 1;
				}
				else
				{
					pos = ptr_n - pSqlData + 1;
				}
			}

			while (pSqlData[pos] == '\r' || pSqlData[pos] == '\n')
			{
				pos += 1;
			}
		}

		if (pos > uiSqlDataLen || pos == uiSqlDataLen)
		{
			break;
		}
		char * pp = &pSqlData[pos];
		sqlerr = sqlite3_prepare_v2(sdb->sdb_p, &pSqlData[pos], -1, &stmt, NULL);
		if (sqlerr != SQLITE_OK)
		{
			goto err;
		}

		do {
			sqlerr = sqlite3_step(stmt);

			if (sqlerr == SQLITE_BUSY) {
				sqlite3_sleep(SDB_BUSY_RETRY_TIME);
			}

			if (sqlerr == SQLITE_DONE)
			{
				sqlerr = SQLITE_OK;
			}

			if (sqlerr == SQLITE_ROW)
			{
				// null;
			}

		} while (!sdb_done(sqlerr, &retry));

		if (sqlerr == SQLITE_ROW)
		{
			sqlerr = SQLITE_OK;
		}

		if (stmt) {
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			stmt = NULL;
		}

		if (sqlerr)
		{
			goto err;
		}

		// next line
		ptr_semicolon = strstr(&pSqlData[pos], ";");

		if (NULL == ptr_semicolon)
		{
			pos = uiSqlDataLen;
			break;
		}
		else
		{
			pos = ptr_semicolon - pSqlData + 1;
		}
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	return sqlerr;
}

unsigned int SMB_CS_ExecSQL(char *pSqlData, unsigned int uiSqlDataLen)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_ExecSQL(&sdb, pSqlData, uiSqlDataLen);
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

	return crv;
}


unsigned int SMB_CS_FindCertChain(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned char *pbCert, unsigned int uiCertLen)
{
	unsigned int ulRet = 0;

	SMB_CS_CertificateContext *ctx = NULL;
	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;
	SMB_CS_CertificateContext_NODE * lastHeader = NULL;
	CertificateItemParse certParse;
	SMB_CS_CertificateFindAttr findAttr = { 0 };

	if (0 != SMB_CS_CreateCtx(&ctx, pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	if (!ctx)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	if (0 != certParse.setCertificate(pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	certParse.parse();

	findAttr.uiFindFlag = 128;
	findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
	findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

	SMB_CS_FindCtx(&findAttr, &ctxHeader);

	for (lastHeader = ctxHeader; ctxHeader != NULL; lastHeader = ctxHeader)
	{
		if (0 != certParse.setCertificate(ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length))
		{
			ulRet = EErr_SMB_INVALID_ARG;
			goto err;
		}

		certParse.parse();

		if (0 == strcmp(certParse.m_strIssueKeyID.c_str(), certParse.m_strSubjectKeyID.c_str()))
		{
			ulRet = EErr_SMB_OK; // success
			break;
		}

		findAttr.uiFindFlag = 128;
		findAttr.stSubjectKeyID.data = (unsigned char*)certParse.m_strIssueKeyID.c_str();
		findAttr.stSubjectKeyID.length = certParse.m_strIssueKeyID.size();

		SMB_CS_FindCtx(&findAttr, &ctxHeader);

		if (lastHeader == ctxHeader)
		{
			break;
		}
	}

err:
	if (ctx)
	{
		SMB_CS_FreeCtx(ctx);
	}

	*ppCertCtxNodeHeader = ctxHeader;

	return ulRet;
}


int sdb_FillCSP(SMB_CS_CSP **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_CSP *pPtr = (SMB_CS_CSP *)malloc(sizeof(SMB_CS_CSP));

	memset(pPtr, 0, sizeof(SMB_CS_CSP));


	//id , name , value

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stName.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stName.data = (unsigned char *)malloc(pPtr->stName.length);
	memcpy(pPtr->stName.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stName.length);

	pos += 1;
	pPtr->stValue.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stValue.data = (unsigned char *)malloc(pPtr->stValue.length);
	memcpy(pPtr->stValue.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stValue.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumCSP(SDB *sdb, SMB_CS_CSP_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_csp;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_CSP *pPtr = NULL;

			sdb_FillCSP(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_EnumCSP(SMB_CS_CSP_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumCSP(&sdb, ppNodeHeader);
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

	return crv;
}


int sdb_FillPIDVID(SMB_CS_PIDVID **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_PIDVID *pPtr = (SMB_CS_PIDVID *)malloc(sizeof(SMB_CS_PIDVID));

	memset(pPtr, 0, sizeof(SMB_CS_PIDVID));


	//id , pid, vid, type

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stPID.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPID.data = (unsigned char *)malloc(pPtr->stPID.length);
	memcpy(pPtr->stPID.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPID.length);

	pos += 1;
	pPtr->stVID.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stVID.data = (unsigned char *)malloc(pPtr->stVID.length);
	memcpy(pPtr->stVID.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stVID.length);

	pos += 1;
	pPtr->stType.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stType.data = (unsigned char *)malloc(pPtr->stType.length);
	memcpy(pPtr->stType.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stType.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumPIDVID(SDB *sdb, SMB_CS_PIDVID_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_pid_vid;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_PIDVID *pPtr = NULL;

			sdb_FillPIDVID(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_EnumPIDVID(SMB_CS_PIDVID_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumPIDVID(&sdb, ppNodeHeader);
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

	return crv;
}


int sdb_FillPath(SMB_CS_Path **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_Path *pPtr = (SMB_CS_Path *)malloc(sizeof(SMB_CS_Path));

	memset(pPtr, 0, sizeof(SMB_CS_Path));


	//id , name, value, digest_md5, digest_sha1

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stName.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stName.data = (unsigned char *)malloc(pPtr->stName.length);
	memcpy(pPtr->stName.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stName.length);

	pos += 1;
	pPtr->stValue.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stValue.data = (unsigned char *)malloc(pPtr->stValue.length);
	memcpy(pPtr->stValue.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stValue.length);

	pos += 1;
	pPtr->stDigestMD5.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stDigestMD5.data = (unsigned char *)malloc(pPtr->stDigestMD5.length);
	memcpy(pPtr->stDigestMD5.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stDigestMD5.length);

	pos += 1;
	pPtr->stDigestSHA1.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stDigestSHA1.data = (unsigned char *)malloc(pPtr->stDigestSHA1.length);
	memcpy(pPtr->stDigestSHA1.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stDigestSHA1.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumPath(SDB *sdb, SMB_CS_Path_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_path;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_Path *pPtr = NULL;

			sdb_FillPath(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_EnumPath(SMB_CS_Path_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumPath(&sdb, ppNodeHeader);
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

	return crv;
}


int sdb_FillSKF(SMB_CS_SKF **ppPtr, sqlite3_stmt *stmt)
{
	SMB_CS_SKF *pPtr = (SMB_CS_SKF *)malloc(sizeof(SMB_CS_SKF));

	memset(pPtr, 0, sizeof(SMB_CS_SKF));

	//id , name, path, signtype

	int pos = -1;

	pos += 1;
	g_mapPtr2IDs[pPtr] = sqlite3_column_int(stmt, pos);

	pos += 1;
	pPtr->stName.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stName.data = (unsigned char *)malloc(pPtr->stName.length);
	memcpy(pPtr->stName.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stName.length);

	pos += 1;
	pPtr->stPath.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPath.data = (unsigned char *)malloc(pPtr->stPath.length);
	memcpy(pPtr->stPath.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPath.length);

	pos += 1;
	pPtr->stSignType.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stSignType.data = (unsigned char *)malloc(pPtr->stSignType.length);
	memcpy(pPtr->stSignType.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stSignType.length);

	pos += 1;
	pPtr->stPinVerify.length = sqlite3_column_bytes(stmt, pos);
	pPtr->stPinVerify.data = (unsigned char *)malloc(pPtr->stPinVerify.length);
	memcpy(pPtr->stPinVerify.data, (char *)sqlite3_column_blob(stmt, pos), pPtr->stPinVerify.length);

	*ppPtr = pPtr;

	return 0;
}

int sdb_EnumSKF(SDB *sdb, SMB_CS_SKF_NODE **ppNodeHeader)
{
	sqlite3_stmt *stmt = NULL;
	int sqlerr = SQLITE_OK;
	int retry = 0;
	int i = 0;

	LOCK_SQLITE();

	sqlerr = sqlite3_prepare_v2(sdb->sdb_p, "select * from table_skf;", -1, &stmt, NULL);
	if (sqlerr != SQLITE_OK)
	{
		goto err;
	}

	do {
		sqlerr = sqlite3_step(stmt);

		if (sqlerr == SQLITE_BUSY) {
			sqlite3_sleep(SDB_BUSY_RETRY_TIME);
		}

		if (sqlerr == SQLITE_DONE)
		{
			sqlerr = SQLITE_OK;
		}

		if (sqlerr == SQLITE_ROW)
		{
			SMB_CS_SKF *pPtr = NULL;

			sdb_FillSKF(&pPtr, stmt);
			OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppNodeHeader, (void *)pPtr);
		}

	} while (!sdb_done(sqlerr, &retry));

	if (sqlerr == SQLITE_ROW)
	{
		sqlerr = SQLITE_OK;
	}

err:
	if (stmt) {
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
	}
	UNLOCK_SQLITE();

	if (!sqlerr)
	{

	}

	return sqlerr;
}

unsigned int SMB_CS_EnumSKF(SMB_CS_SKF_NODE **ppNodeHeader)
{
	unsigned int ulRet = -1;
	int crv = 0;
	SDB sdb = { 0 };

	sdb.sdb_path = smb_db_path;

	crv = sdb_Begin(&sdb);
	if (crv)
	{
		goto err;
	}

	crv = sdb_EnumSKF(&sdb, ppNodeHeader);
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

	return crv;
}

unsigned int SMB_CS_FreeCSPLink(SMB_CS_CSP_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreeCSP((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

unsigned int SMB_CS_FreeSKFLink(SMB_CS_SKF_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreeSKF((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

unsigned int SMB_CS_FreePIDVIDLink(SMB_CS_PIDVID_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreePIDVID((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

unsigned int SMB_CS_FreePathLink(SMB_CS_Path_NODE **ppNodeHeader)
{
	while (*ppNodeHeader)
	{
		SMB_CS_FreePath((*ppNodeHeader)->ptr_data);
		OPF_DelNoFreeHandleNodeDataFromLink((OPST_HANDLE_NODE**)ppNodeHeader, (*ppNodeHeader)->ptr_data);
	}

	return 0;
}

unsigned int SMB_CS_FreePath(SMB_CS_Path *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stDigestMD5.data)
		{
			free(pPtr->stDigestMD5.data);
			pPtr->stDigestMD5.data = NULL;
		}

		if (pPtr->stDigestSHA1.data)
		{
			free(pPtr->stDigestSHA1.data);
			pPtr->stDigestSHA1.data = NULL;
		}

		if (pPtr->stName.data)
		{
			free(pPtr->stName.data);
			pPtr->stName.data = NULL;
		}

		if (pPtr->stValue.data)
		{
			free(pPtr->stValue.data);
			pPtr->stValue.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

unsigned int SMB_CS_FreeCSP(SMB_CS_CSP *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stName.data)
		{
			free(pPtr->stName.data);
			pPtr->stName.data = NULL;
		}

		if (pPtr->stValue.data)
		{
			free(pPtr->stValue.data);
			pPtr->stValue.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

unsigned int SMB_CS_FreeSKF(SMB_CS_SKF *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stName.data)
		{
			free(pPtr->stName.data);
			pPtr->stName.data = NULL;
		}

		if (pPtr->stPath.data)
		{
			free(pPtr->stPath.data);
			pPtr->stPath.data = NULL;
		}

		if (pPtr->stSignType.data)
		{
			free(pPtr->stSignType.data);
			pPtr->stSignType.data = NULL;
		}

		if (pPtr->stPinVerify.data)
		{
			free(pPtr->stPinVerify.data);
			pPtr->stPinVerify.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}

unsigned int SMB_CS_FreePIDVID(SMB_CS_PIDVID *pPtr)
{
	if (pPtr)
	{
		if (pPtr->stPID.data)
		{
			free(pPtr->stPID.data);
			pPtr->stPID.data = NULL;
		}

		if (pPtr->stVID.data)
		{
			free(pPtr->stVID.data);
			pPtr->stVID.data = NULL;
		}

		if (pPtr->stType.data)
		{
			free(pPtr->stType.data);
			pPtr->stType.data = NULL;
		}

		free(pPtr);
		pPtr = NULL;
	}

	return 0;
}