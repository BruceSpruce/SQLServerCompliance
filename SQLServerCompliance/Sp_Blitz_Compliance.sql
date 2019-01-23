-- 1. WGRANIE NAJNOWSZEGO SP_BLITZ'a (SP_BLITXCACHE i SP_BLITZ)

/*
	INSTALL STRUCTURE
	CREATE DATABASE _SQL_ IF YOU NEED!
*/

USE _SQL_;
GO
CREATE SCHEMA [COMP];
GO
CREATE TABLE COMP.BlitzChecksToSkip 
(
	ID INT IDENTITY (1,1) CONSTRAINT PK_ID_BlitzChecksToSkip PRIMARY KEY CLUSTERED,
	ServerName NVARCHAR(128), 
	DatabaseName NVARCHAR(128), 
	CheckID INT
);

/*
	WYKLUCZENIA
	SELECT * FROM COMP.BlitzChecksToSkip
*/

INSERT INTO COMP.BlitzChecksToSkip 
  (ServerName, DatabaseName, CheckID)
  VALUES(NULL, 'DMS', 16);
GO

/*
    WEAK PASSWORDS
    CREATE TABLE AND DICTIONARY

    SELECT [Passwd]
    FROM [_SQL_].[COMP].[WeakPwd]
*/
USE [_SQL_];
GO

CREATE TABLE [COMP].[WeakPwd](
       [Passwd] [nvarchar](255) NOT NULL INDEX IX_Passwd CLUSTERED
) ON [PRIMARY]
GO

-- IMPORT DATA
BULK INSERT COMP.WeakPwd
FROM 'C:\temp\weak_passwords_list.txt'
WITH
(
    FIRSTROW = 1,
    FIELDTERMINATOR = '||||||||', --CSV field delimiter
    ROWTERMINATOR = '\n',         --Use to shift the control to next row
    ERRORFILE = 'C:\temp\errorlog.txt',
    TABLOCK
);


/*
	PROCEDURA COMPLIANCE
*/
USE [_SQL_]
GO
----
IF NOT EXISTS (
  SELECT 1 
    FROM INFORMATION_SCHEMA.ROUTINES 
   WHERE SPECIFIC_SCHEMA = N'COMP'
     AND SPECIFIC_NAME = N'spBlitzCompliance' 
)
   EXEC ('CREATE PROCEDURE [COMP].[spBlitzCompliance] AS SELECT 1');
GO
---

---
ALTER PROCEDURE [COMP].[spBlitzCompliance]
	( @IsPROD BIT = 1
	 ,@SendEmail BIT = 1
	 ,@MailProfile NVARCHAR(128) = 'mail_profile'
	 ,@recipients NVARCHAR(128) = 'recipients@domain.pl'
	)
AS
	EXEC master.dbo.sp_Blitz	@OutputDatabaseName = '_SQL_',
								@OutputSchemaName = 'COMP',
								@OutputTableName = 'SP_BLITZ',
								@SkipChecksDatabase = '_SQL_', 
								@SkipChecksSchema = 'COMP', 
								@SkipChecksTable = 'BlitzChecksToSkip';;

	-- STANDARDOWE WYKLUCZENIA CHECK�W
	DELETE FROM [_SQL_].[COMP].[SP_BLITZ] WHERE Priority IN (0, 254, 255);
	DELETE FROM [_SQL_].[COMP].[SP_BLITZ] WHERE CheckID IN (3, 107, 150, 10, 11, 78, 32, 80, 74, 76, 105, 123, 173, 176, 1009, 1011, 1012, 1020, 1026, 1029, 1031, 1049, 1071, 1072, 1073, 1076, 133, 8, 57, 203, 210, 45, 44, 19, 1032, 1036, 1054, 199, 208, 186, 77, 53);
	DELETE FROM [_SQL_].[COMP].[SP_BLITZ] WHERE Details LIKE '%user %db_app_owner% has the role %db_ddladmin%';
	DELETE FROM [_SQL_].[COMP].[SP_BLITZ] WHERE Details LIKE '%Database distribution is compatibility level 90%';
	DELETE FROM [_SQL_].[COMP].[SP_BLITZ] WHERE Details LIKE '%Stored procedure%master%sp_MSrepl_startup%runs automatically when SQL Server starts up.%';

	IF (@IsPROD = 0)
	BEGIN -- WYKLUCZENIA DLA INSTANCJI TESTOWYCH
		DELETE FROM [_SQL_].[COMP].[SP_BLITZ] WHERE CheckID IN (47, 160, 38, 48, 39, 122, 124, 117, 36, 96, 61, 30, 93) AND CheckDate >= (SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ]);
	END

	-- CZY W��CZONY KERBEROS
	IF NOT EXISTS (
		SELECT 1 FROM sys.dm_exec_connections WHERE auth_scheme = 'KERBEROS'
		)
	INSERT INTO [COMP].[SP_BLITZ] VALUES
           (@@SERVERNAME
           ,(SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ])
           ,1
           ,'Security'
           ,'Kerberos Authentication'
           ,NULL
           ,NULL
           ,'SPN not configured or may no one session are connected by windows authentication'
           ,NULL
           ,NULL
           ,10001);

	-- CZY W��CZONE SZYFROWANIE
	IF NOT EXISTS (
		SELECT 1 FROM sys.dm_exec_connections WHERE encrypt_option = 'TRUE'
		)
	INSERT INTO [COMP].[SP_BLITZ] VALUES
           (@@SERVERNAME
           ,(SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ])
           ,1
           ,'Security'
           ,'Encrypted Connections'
           ,NULL
           ,NULL
           ,'Encrypted Connections not cofigured'
           ,NULL
           ,NULL
           ,10002);
    
    -- CZY S� HAS�A TAKIE JAK LOGINY
    IF EXISTS (
		select 1 from sys.sql_logins where pwdcompare(name, password_hash) = 1
		)
	INSERT INTO [COMP].[SP_BLITZ] VALUES
           (@@SERVERNAME
           ,(SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ])
           ,1
           ,'Security'
           ,'Weak passwords'
           ,NULL
           ,NULL
           ,'Found SQL login with password same as name'
           ,NULL
           ,NULL
           ,10003);

    -- CZY S� PUSTE HAS�A
    IF EXISTS (
		select 1 from sys.sql_logins where pwdcompare('', password_hash) = 1
		)
	INSERT INTO [COMP].[SP_BLITZ] VALUES
           (@@SERVERNAME
           ,(SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ])
           ,1
           ,'Security'
           ,'Weak passwords'
           ,NULL
           ,NULL
           ,'Found SQL login with blank password'
           ,NULL
           ,NULL
           ,10004);

    -- CZY S� S�ABE HAS�A
    IF EXISTS (
		SELECT 1 FROM sys.sql_logins t1
        INNER JOIN [COMP].[WeakPwd] t2
        ON (
               PWDCOMPARE(t2.Passwd, t1.password_hash) = 1
               OR PWDCOMPARE(REPLACE(t2.Passwd, '@@Name', t1.name), t1.password_hash) = 1
           )
		)
	INSERT INTO [COMP].[SP_BLITZ] VALUES
           (@@SERVERNAME
           ,(SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ])
           ,1
           ,'Security'
           ,'Weak passwords'
           ,NULL
           ,NULL
           ,'Found SQL login with weak password'
           ,NULL
           ,NULL
           ,10004);

	IF (@SendEmail = 1)
	BEGIN
		-- RAPORT NA EMAIL --
		IF OBJECT_ID('tempdb.dbo.#TempRap', 'U') IS NOT NULL
			DROP TABLE #TempRap;
		-- DEFINE VARIABLES
		DECLARE @TableTail NVARCHAR(MAX);
		DECLARE @TableHead NVARCHAR(MAX);
		DECLARE @Body NVARCHAR(MAX);
		DECLARE @Subject NVARCHAR(MAX);
		-- GET SERVERNAME AND CHECKDATE
		DECLARE @SERVERNAME NVARCHAR(128) = (SELECT DISTINCT ServerName FROM [_SQL_].[COMP].[SP_BLITZ]);
		DECLARE @CheckDate DateTime2 = (SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ]);
		-- GET DATA TO REPORT
		SELECT	ID,
			Priority,
			FindingsGroup,
			Finding,
			DatabaseName,
			Details,
			CheckID
		INTO #TempRap
		FROM [_SQL_].[COMP].[SP_BLITZ]
		WHERE
			CheckDate >= (SELECT MAX(CheckDate) FROM [_SQL_].[COMP].[SP_BLITZ]);
		--PREPARE REPORT
		SET @TableTail = '</table>';
		SET @TableHead = '<html><head>' +
						  '<style>' +
						  'td {border: solid black 1px;padding-left:5px;padding-right:5px;padding-top:1px;padding-bottom:1px;font-size:11pt;} ' +
						  '</style>' +
						  '</head>' +
						  '<body><table cellpadding=0 cellspacing=0 border=0><caption>COMPLIANCE REPORT FOR ' + @SERVERNAME + '. DATE: ' + CONVERT(CHAR(19), @CheckDate, 121) + '</caption>' +
						  '<tr bgcolor=#c0f4c3>' +
						  '<td align=center><b>ID</b></td>' +
						  '<td align=center><b>Priority</b></td>' +
						  '<td align=center><b>Findings Group</b></td>' +
						  '<td align=center><b>Finding</b></td>' +
						  '<td align=center><b>Database Name</b></td>' +
						  '<td align=center><b>Details</b></td>' +
						  '<td align=center><b>CheckID</b></td>';
		Select @Body = (SELECT ID AS [TD align=right]
							  ,ISNULL(Priority, 0) AS [TD align=left]
							  ,ISNULL(FindingsGroup, 'n/a') AS [TD align=center]
							  ,ISNULL(Finding, 'n/a') AS [TD align=center]
							  ,ISNULL(DatabaseName, '') AS [TD align=left]
							  ,ISNULL(Details, 'n/a') AS [TD align=left]
							  ,ISNULL(CheckID, 0) AS [TD align=right]
							  FROM #TempRap					
						ORDER BY Priority ASC
						For XML raw('tr'), Elements);
		-- Replace the entity codes and row numbers
		Set @Body = Replace(@Body, '_x0020_', space(1))
		Set @Body = Replace(@Body, '_x003D_', '=')
		-- CREATE HTML BODY 
		Select @Body = @TableHead + @Body + @TableTail + '</br></br>Compliance SQL Server Instance 2017 v1.01</body></html>';
		-- SEND EMAIL
		SET @Subject = '[' + @@servername + '] COMPLIANCE REPORT OF ' +  CONVERT(CHAR(10), GETDATE(), 121)
		-- return output
		EXEC msdb.dbo.sp_send_dbmail
					@profile_name = @MailProfile,
					@recipients = @recipients,
					@body =  @Body,
					@subject = @Subject,
					@body_format = 'HTML';
	END


--- PRZYK�ADOWE WYWO�ANIA ---
EXEC [COMP].[spBlitzCompliance] @IsPROD = 0; -- Dla instancji nieprodukcyjnej
EXEC [COMP].[spBlitzCompliance] @IsPROD = 1; -- Dla instancji produkcyjnej
EXEC [COMP].[spBlitzCompliance] @IsPROD = 1, @recipients = 'recipients@domain.pl' -- dla instancji nieprodukcyjnej i raport ma by� wys�any dla mireks