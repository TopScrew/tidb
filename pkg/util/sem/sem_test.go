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
	"github.com/pingcap/tidb/pkg/sessionctx/variable"
	"testing"

	"github.com/pingcap/tidb/pkg/parser/mysql"
	"github.com/stretchr/testify/assert"
)

func TestInvisibleSchema(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsInvisibleSchema(metricsSchema))
	assert.True(IsInvisibleSchema("METRICS_ScHEma"))
	assert.False(IsInvisibleSchema("mysql"))
	assert.False(IsInvisibleSchema(informationSchema))
	assert.False(IsInvisibleSchema("Bogusname"))
}

func TestIsInvisibleTable(t *testing.T) {
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

	assert.True(HasRestrictedPrivilegePrefix("RESTRICTED_TABLES_ADMIN"))
	assert.True(HasRestrictedPrivilegePrefix("RESTRICTED_STATUS_VARIABLES_ADMIN"))
	assert.False(HasRestrictedPrivilegePrefix("CONNECTION_ADMIN"))
	assert.False(HasRestrictedPrivilegePrefix("BACKUP_ADMIN"))
	assert.False(HasRestrictedPrivilegePrefix("aa"))
}

func TestGetRestrictedStatusOfStateVariable(t *testing.T) {
	assert := assert.New(t)

	tidbCfg := config.NewConfig()

	tidbCfg.Security.SEM.RestrictedStatus = []config.RestrictedState{
		{
			Name:            "tidb_gc_leader_desc",
			RestrictionType: "hidden",
			Value:           "",
		},
		{
			Name:            "server_id",
			RestrictionType: "replace",
			Value:           "xxxx",
		},
	}

	config.StoreGlobalConfig(tidbCfg)

	var restricted bool
	var info *config.RestrictedState

	restricted, info = GetRestrictedStatusOfStateVariable(tidbGCLeaderDesc)
	assert.True(restricted)
	assert.Equal("tidb_gc_leader_desc", info.Name)
	assert.Equal("hidden", info.RestrictionType)

	restricted, info = GetRestrictedStatusOfStateVariable("server_id")
	assert.True(restricted)
	assert.Equal("server_id", info.Name)
	assert.Equal("replace", info.RestrictionType)
	assert.Equal("xxxx", info.Value)

	restricted, info = GetRestrictedStatusOfStateVariable("ddl_schema_version")
	assert.False(restricted)

	restricted, info = GetRestrictedStatusOfStateVariable("Ssl_version")
	assert.False(restricted)
}

func TestIsStaticPermissionRestricted(t *testing.T) {

	tidbCfg := config.NewConfig()
	p := make(map[mysql.PrivilegeType]struct{})
	p[mysql.ConfigPriv] = struct{}{}
	p[mysql.ShutdownPriv] = struct{}{}
	tidbCfg.Security.SEM.RestrictedStaticPrivileges = p
	config.StoreGlobalConfig(tidbCfg)
	assert := assert.New(t)
	assert.True(IsStaticPermissionRestricted(mysql.ConfigPriv))
	assert.False(IsStaticPermissionRestricted(mysql.AlterPriv))
	assert.True(IsStaticPermissionRestricted(mysql.ShutdownPriv))
	assert.False(IsStaticPermissionRestricted(mysql.CreatePriv))
	assert.False(IsStaticPermissionRestricted(mysql.AllPriv))
}

func TestIsInvisibleSysVar(t *testing.T) {
	assert := assert.New(t)

	assert.False(IsInvisibleSysVar(variable.Hostname))                   // changes the value to default, but is not invisible
	assert.False(IsInvisibleSysVar(variable.TiDBEnableEnhancedSecurity)) // should be able to see the mode is on.
	assert.False(IsInvisibleSysVar(variable.TiDBAllowRemoveAutoInc))

	assert.True(IsInvisibleSysVar(variable.TiDBCheckMb4ValueInUTF8))
	assert.True(IsInvisibleSysVar(variable.TiDBConfig))
	assert.True(IsInvisibleSysVar(variable.TiDBEnableSlowLog))
	assert.True(IsInvisibleSysVar(variable.TiDBExpensiveQueryTimeThreshold))
	assert.True(IsInvisibleSysVar(variable.TiDBForcePriority))
	assert.True(IsInvisibleSysVar(variable.TiDBGeneralLog))
	assert.True(IsInvisibleSysVar(variable.TiDBMetricSchemaRangeDuration))
	assert.True(IsInvisibleSysVar(variable.TiDBMetricSchemaStep))
	assert.True(IsInvisibleSysVar(variable.TiDBOptWriteRowID))
	assert.True(IsInvisibleSysVar(variable.TiDBPProfSQLCPU))
	assert.True(IsInvisibleSysVar(variable.TiDBRecordPlanInSlowLog))
	assert.True(IsInvisibleSysVar(variable.TiDBSlowQueryFile))
	assert.True(IsInvisibleSysVar(variable.TiDBSlowLogThreshold))
	assert.True(IsInvisibleSysVar(variable.TiDBEnableCollectExecutionInfo))
	assert.True(IsInvisibleSysVar(variable.TiDBMemoryUsageAlarmRatio))
	assert.True(IsInvisibleSysVar(variable.TiDBEnableTelemetry))
	assert.True(IsInvisibleSysVar(variable.TiDBRowFormatVersion))
	assert.True(IsInvisibleSysVar(variable.TiDBRedactLog))
	assert.True(IsInvisibleSysVar(variable.TiDBTopSQLMaxTimeSeriesCount))
	assert.True(IsInvisibleSysVar(variable.TiDBTopSQLMaxTimeSeriesCount))
	assert.True(IsInvisibleSysVar(tidbAuditRetractLog))
}
