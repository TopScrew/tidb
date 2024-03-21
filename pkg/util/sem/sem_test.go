// Copyright 2021 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sem

import (
	"github.com/pingcap/tidb/pkg/config"
	"testing"

	"github.com/pingcap/tidb/pkg/parser/mysql"
	"github.com/pingcap/tidb/pkg/sessionctx/variable"
	"github.com/stretchr/testify/assert"
)

func TestInvisibleSchema(t *testing.T) {
	tidbCfg := config.NewConfig()
	tidbCfg.Security.SEM.RestrictedDatabases = []string{metricsSchema}
	config.StoreGlobalConfig(tidbCfg)

	assert := assert.New(t)

	assert.True(IsInvisibleSchema(metricsSchema))
	assert.True(IsInvisibleSchema("METRICS_ScHEma"))
	assert.False(IsInvisibleSchema("mysql"))
	assert.False(IsInvisibleSchema(informationSchema))
	assert.False(IsInvisibleSchema("Bogusname"))
}

func TestIsInvisibleTable(t *testing.T) {
	tidbCfg := config.NewConfig()
	tidbCfg.Security.SEM.RestrictedTables = []config.RestrictedTable{
		{
			Schema: mysql.SystemDB,
			Name:   exprPushdownBlacklist,
		},
		{
			Schema: mysql.SystemDB,
			Name:   gcDeleteRange,
		},
		{
			Schema: mysql.SystemDB,
			Name:   gcDeleteRangeDone,
		},
		{
			Schema: mysql.SystemDB,
			Name:   optRuleBlacklist,
		},
		{
			Schema: mysql.SystemDB,
			Name:   tidb,
		},
		{
			Schema: mysql.SystemDB,
			Name:   globalVariables,
		},
		{
			Schema: informationSchema,
			Name:   clusterConfig,
		},
		{
			Schema: informationSchema,
			Name:   clusterHardware,
		},
		{
			Schema: informationSchema,
			Name:   clusterLoad,
		},
		{
			Schema: informationSchema,
			Name:   clusterLog,
		},
		{
			Schema: informationSchema,
			Name:   clusterSystemInfo,
		},
		{
			Schema: informationSchema,
			Name:   inspectionResult,
		},
		{
			Schema: informationSchema,
			Name:   inspectionRules,
		},
		{
			Schema: informationSchema,
			Name:   inspectionSummary,
		},
		{
			Schema: informationSchema,
			Name:   metricsSummary,
		},
		{
			Schema: informationSchema,
			Name:   metricsSummaryByLabel,
		},
		{
			Schema: informationSchema,
			Name:   metricsTables,
		},
		{
			Schema: informationSchema,
			Name:   tidbHotRegions,
		},
		{
			Schema: performanceSchema,
			Name:   pdProfileAllocs,
		},
		{
			Schema: performanceSchema,
			Name:   pdProfileBlock,
		},
		{
			Schema: performanceSchema,
			Name:   pdProfileCPU,
		},
		{
			Schema: performanceSchema,
			Name:   pdProfileGoroutines,
		},
		{
			Schema: performanceSchema,
			Name:   pdProfileMemory,
		},
		{
			Schema: performanceSchema,
			Name:   pdProfileMutex,
		},
		{
			Schema: performanceSchema,
			Name:   tidbProfileAllocs,
		},
		{
			Schema: performanceSchema,
			Name:   tidbProfileBlock,
		},
		{
			Schema: performanceSchema,
			Name:   tidbProfileCPU,
		},
		{
			Schema: performanceSchema,
			Name:   tidbProfileGoroutines,
		},
		{
			Schema: performanceSchema,
			Name:   tidbProfileMemory,
		},
		{
			Schema: performanceSchema,
			Name:   tidbProfileMutex,
		},
		{
			Schema: performanceSchema,
			Name:   tikvProfileCPU,
		},
	}
	tidbCfg.Security.SEM.RestrictedDatabases = []string{metricsSchema}
	config.StoreGlobalConfig(tidbCfg)

	assert := assert.New(t)

	mysqlTbls := []string{exprPushdownBlacklist, gcDeleteRange, gcDeleteRangeDone, optRuleBlacklist, tidb, globalVariables}
	infoSchemaTbls := []string{clusterConfig, clusterHardware, clusterLoad, clusterLog, clusterSystemInfo, inspectionResult,
		inspectionRules, inspectionSummary, metricsSummary, metricsSummaryByLabel, metricsTables, tidbHotRegions}
	perfSChemaTbls := []string{pdProfileAllocs, pdProfileBlock, pdProfileCPU, pdProfileGoroutines, pdProfileMemory,
		pdProfileMutex, tidbProfileAllocs, tidbProfileBlock, tidbProfileCPU, tidbProfileGoroutines,
		tidbProfileMemory, tidbProfileMutex, tikvProfileCPU}

	for _, tbl := range mysqlTbls {
		assert.True(IsInvisibleTable(mysql.SystemDB, tbl))
	}
	for _, tbl := range infoSchemaTbls {
		assert.True(IsInvisibleTable(informationSchema, tbl))
	}
	for _, tbl := range perfSChemaTbls {
		assert.True(IsInvisibleTable(performanceSchema, tbl))
	}

	assert.True(IsInvisibleTable(metricsSchema, "acdc"))
	assert.True(IsInvisibleTable(metricsSchema, "fdsgfd"))
	assert.False(IsInvisibleTable("test", "t1"))
}

func TestIsRestrictedPrivilege(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsRestrictedPrivilege("RESTRICTED_TABLES_ADMIN"))
	assert.True(IsRestrictedPrivilege("RESTRICTED_STATUS_VARIABLES_ADMIN"))
	assert.False(IsRestrictedPrivilege("CONNECTION_ADMIN"))
	assert.False(IsRestrictedPrivilege("BACKUP_ADMIN"))
	assert.False(IsRestrictedPrivilege("aa"))
}

func TestIsInvisibleStatusVar(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsInvisibleStatusVar(tidbGCLeaderDesc))
	assert.False(IsInvisibleStatusVar("server_id"))
	assert.False(IsInvisibleStatusVar("ddl_schema_version"))
	assert.False(IsInvisibleStatusVar("Ssl_version"))
}

func TestIsInvisibleSysVar(t *testing.T) {
	tidbCfg := config.NewConfig()
	tidbCfg.Security.SEM.RestrictedVariables = []config.RestrictedVariable{
		{
			Name:            variable.Hostname,
			RestrictionType: "replace",
			Value:           "localhost",
		},
		{
			Name:            variable.TiDBEnableEnhancedSecurity,
			RestrictionType: "replace",
			Value:           "ON",
		},
		{
			Name:            variable.TiDBAllowRemoveAutoInc,
			RestrictionType: "replace",
			Value:           "True",
		},
		{
			Name:            variable.TiDBCheckMb4ValueInUTF8,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBConfig,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBEnableSlowLog,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBExpensiveQueryTimeThreshold,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBForcePriority,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBGeneralLog,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBMetricSchemaRangeDuration,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBMetricSchemaStep,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBOptWriteRowID,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBPProfSQLCPU,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBRecordPlanInSlowLog,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBSlowQueryFile,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBSlowLogThreshold,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBEnableCollectExecutionInfo,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBMemoryUsageAlarmRatio,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBEnableTelemetry,
			RestrictionType: "hidden",
			Value:           "",
		},
		// This line is commented out, assuming variable.TiDBEnableTelemetry should be excluded
		{
			Name:            variable.TiDBRowFormatVersion,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBRedactLog,
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            variable.TiDBTopSQLMaxTimeSeriesCount,
			RestrictionType: "hidden",
			Value:           "",
		},
		// Assuming tidbAuditRetractLog is a variable, if it's not, you might need to adjust
		{
			Name:            tidbAuditRetractLog,
			RestrictionType: "hidden",
			Value:           "",
		},
	}

	config.StoreGlobalConfig(tidbCfg)
	assert := assert.New(t)
	assert.False(IsInvisibleSysVar(variable.Hostname))                   // changes the value to default, but is not invisible
	assert.False(IsInvisibleSysVar(variable.TiDBEnableEnhancedSecurity)) // should be able to see the mode is on.
	assert.False(IsInvisibleSysVar(variable.TiDBAllowRemoveAutoInc))
	assert.True(IsInvisibleSysVar(variable.TiDBSlowLogThreshold))
	assert.True(IsInvisibleSysVar(variable.TiDBEnableCollectExecutionInfo))
	assert.True(IsInvisibleSysVar(variable.TiDBMemoryUsageAlarmRatio))
	assert.True(IsInvisibleSysVar(variable.TiDBEnableTelemetry))
	assert.True(IsInvisibleSysVar(variable.TiDBRowFormatVersion))
	assert.True(IsInvisibleSysVar(variable.TiDBRedactLog))
	assert.True(IsInvisibleSysVar(variable.TiDBTopSQLMaxTimeSeriesCount))
}
