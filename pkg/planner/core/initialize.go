// Copyright 2017 PingCAP, Inc.
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

package core

import (
	"github.com/pingcap/tidb/pkg/expression"
	"github.com/pingcap/tidb/pkg/kv"
	"github.com/pingcap/tidb/pkg/planner/core/internal/base"
	"github.com/pingcap/tidb/pkg/planner/property"
	"github.com/pingcap/tidb/pkg/types"
	"github.com/pingcap/tidb/pkg/util/codec"
	"github.com/pingcap/tidb/pkg/util/plancodec"
	"github.com/pingcap/tidb/pkg/util/size"
)

// Init initializes LogicalAggregation.
func (la LogicalAggregation) Init(ctx PlanContext, offset int) *LogicalAggregation {
	la.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeAgg, &la, offset)
	return &la
}

// Init initializes LogicalJoin.
func (p LogicalJoin) Init(ctx PlanContext, offset int) *LogicalJoin {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeJoin, &p, offset)
	return &p
}

// Init initializes DataSource.
func (ds DataSource) Init(ctx PlanContext, offset int) *DataSource {
	ds.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeDataSource, &ds, offset)
	return &ds
}

// Init initializes TiKVSingleGather.
func (sg TiKVSingleGather) Init(ctx PlanContext, offset int) *TiKVSingleGather {
	sg.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeTiKVSingleGather, &sg, offset)
	return &sg
}

// Init initializes LogicalTableScan.
func (ts LogicalTableScan) Init(ctx PlanContext, offset int) *LogicalTableScan {
	ts.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeTableScan, &ts, offset)
	return &ts
}

// Init initializes LogicalIndexScan.
func (is LogicalIndexScan) Init(ctx PlanContext, offset int) *LogicalIndexScan {
	is.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeIdxScan, &is, offset)
	return &is
}

// Init initializes LogicalApply.
func (la LogicalApply) Init(ctx PlanContext, offset int) *LogicalApply {
	la.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeApply, &la, offset)
	return &la
}

// Init initializes LogicalSelection.
func (p LogicalSelection) Init(ctx PlanContext, qbOffset int) *LogicalSelection {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeSel, &p, qbOffset)
	return &p
}

// Init initializes PhysicalSelection.
func (p PhysicalSelection) Init(ctx PlanContext, stats *property.StatsInfo, qbOffset int, props ...*property.PhysicalProperty) *PhysicalSelection {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeSel, &p, qbOffset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalUnionScan.
func (p LogicalUnionScan) Init(ctx PlanContext, qbOffset int) *LogicalUnionScan {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeUnionScan, &p, qbOffset)
	return &p
}

// Init initializes LogicalProjection.
func (p LogicalProjection) Init(ctx PlanContext, qbOffset int) *LogicalProjection {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeProj, &p, qbOffset)
	return &p
}

// Init initializes LogicalProjection.
func (p LogicalExpand) Init(ctx PlanContext, offset int) *LogicalExpand {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeExpand, &p, offset)
	return &p
}

// Init initializes PhysicalProjection.
func (p PhysicalProjection) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalProjection {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeProj, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalUnionAll.
func (p LogicalUnionAll) Init(ctx PlanContext, offset int) *LogicalUnionAll {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeUnion, &p, offset)
	return &p
}

// Init initializes LogicalPartitionUnionAll.
func (p LogicalPartitionUnionAll) Init(ctx PlanContext, offset int) *LogicalPartitionUnionAll {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypePartitionUnion, &p, offset)
	return &p
}

// Init initializes PhysicalUnionAll.
func (p PhysicalUnionAll) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalUnionAll {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeUnion, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalSort.
func (ls LogicalSort) Init(ctx PlanContext, offset int) *LogicalSort {
	ls.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeSort, &ls, offset)
	return &ls
}

// Init initializes PhysicalSort.
func (p PhysicalSort) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalSort {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeSort, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes NominalSort.
func (p NominalSort) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *NominalSort {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeSort, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalTopN.
func (lt LogicalTopN) Init(ctx PlanContext, offset int) *LogicalTopN {
	lt.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeTopN, &lt, offset)
	return &lt
}

// Init initializes PhysicalTopN.
func (p PhysicalTopN) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalTopN {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeTopN, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalLimit.
func (p LogicalLimit) Init(ctx PlanContext, offset int) *LogicalLimit {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeLimit, &p, offset)
	return &p
}

// Init initializes PhysicalLimit.
func (p PhysicalLimit) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalLimit {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeLimit, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalTableDual.
func (p LogicalTableDual) Init(ctx PlanContext, offset int) *LogicalTableDual {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeDual, &p, offset)
	return &p
}

// Init initializes PhysicalTableDual.
func (p PhysicalTableDual) Init(ctx PlanContext, stats *property.StatsInfo, offset int) *PhysicalTableDual {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeDual, &p, offset)
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalMaxOneRow.
func (p LogicalMaxOneRow) Init(ctx PlanContext, offset int) *LogicalMaxOneRow {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeMaxOneRow, &p, offset)
	return &p
}

// Init initializes PhysicalMaxOneRow.
func (p PhysicalMaxOneRow) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalMaxOneRow {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeMaxOneRow, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes LogicalWindow.
func (p LogicalWindow) Init(ctx PlanContext, offset int) *LogicalWindow {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeWindow, &p, offset)
	return &p
}

// Init initializes PhysicalWindow.
func (p PhysicalWindow) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalWindow {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeWindow, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalShuffle.
func (p PhysicalShuffle) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalShuffle {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeShuffle, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalShuffleReceiverStub.
func (p PhysicalShuffleReceiverStub) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalShuffleReceiverStub {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeShuffleReceiver, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes Update.
func (p Update) Init(ctx PlanContext) *Update {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeUpdate, 0)
	return &p
}

// Init initializes Delete.
func (p Delete) Init(ctx PlanContext) *Delete {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeDelete, 0)
	return &p
}

// Init initializes Insert.
func (p Insert) Init(ctx PlanContext) *Insert {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeInsert, 0)
	return &p
}

// Init initializes LoadData.
func (p LoadData) Init(ctx PlanContext) *LoadData {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeLoadData, 0)
	return &p
}

// Init initializes ImportInto.
func (p ImportInto) Init(ctx PlanContext) *ImportInto {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeImportInto, 0)
	return &p
}

// Init initializes LogicalShow.
func (p LogicalShow) Init(ctx PlanContext) *LogicalShow {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeShow, &p, 0)
	return &p
}

// Init initializes LogicalShowDDLJobs.
func (p LogicalShowDDLJobs) Init(ctx PlanContext) *LogicalShowDDLJobs {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeShowDDLJobs, &p, 0)
	return &p
}

// Init initializes PhysicalShow.
func (p PhysicalShow) Init(ctx PlanContext) *PhysicalShow {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeShow, &p, 0)
	// Just use pseudo stats to avoid panic.
	p.SetStats(&property.StatsInfo{RowCount: 1})
	return &p
}

// Init initializes PhysicalShowDDLJobs.
func (p PhysicalShowDDLJobs) Init(ctx PlanContext) *PhysicalShowDDLJobs {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeShowDDLJobs, &p, 0)
	// Just use pseudo stats to avoid panic.
	p.SetStats(&property.StatsInfo{RowCount: 1})
	return &p
}

// Init initializes LogicalLock.
func (p LogicalLock) Init(ctx PlanContext) *LogicalLock {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeLock, &p, 0)
	return &p
}

// Init initializes PhysicalLock.
func (p PhysicalLock) Init(ctx PlanContext, stats *property.StatsInfo, props ...*property.PhysicalProperty) *PhysicalLock {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeLock, &p, 0)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalTableScan.
func (p PhysicalTableScan) Init(ctx PlanContext, offset int) *PhysicalTableScan {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeTableScan, &p, offset)
	return &p
}

// Init initializes PhysicalIndexScan.
func (p PhysicalIndexScan) Init(ctx PlanContext, offset int) *PhysicalIndexScan {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeIdxScan, &p, offset)
	return &p
}

// Init initializes LogicalMemTable.
func (p LogicalMemTable) Init(ctx PlanContext, offset int) *LogicalMemTable {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeMemTableScan, &p, offset)
	return &p
}

// Init initializes PhysicalMemTable.
func (p PhysicalMemTable) Init(ctx PlanContext, stats *property.StatsInfo, offset int) *PhysicalMemTable {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeMemTableScan, &p, offset)
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalHashJoin.
func (p PhysicalHashJoin) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalHashJoin {
	tp := plancodec.TypeHashJoin
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, tp, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalMergeJoin.
func (p PhysicalMergeJoin) Init(ctx PlanContext, stats *property.StatsInfo, offset int) *PhysicalMergeJoin {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeMergeJoin, &p, offset)
	p.SetStats(stats)
	return &p
}

// Init initializes basePhysicalAgg.
func (base basePhysicalAgg) Init(ctx PlanContext, stats *property.StatsInfo, offset int) *basePhysicalAgg {
	base.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeHashAgg, &base, offset)
	base.SetStats(stats)
	return &base
}

func (base basePhysicalAgg) initForHash(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalHashAgg {
	p := &PhysicalHashAgg{base}
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeHashAgg, p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return p
}

func (base basePhysicalAgg) initForStream(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalStreamAgg {
	p := &PhysicalStreamAgg{base}
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeStreamAgg, p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return p
}

// Init initializes PhysicalApply.
func (p PhysicalApply) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalApply {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeApply, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalUnionScan.
func (p PhysicalUnionScan) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalUnionScan {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeUnionScan, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalIndexLookUpReader.
func (p PhysicalIndexLookUpReader) Init(ctx PlanContext, offset int) *PhysicalIndexLookUpReader {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeIndexLookUp, &p, offset)
	p.TablePlans = flattenPushDownPlan(p.tablePlan)
	p.IndexPlans = flattenPushDownPlan(p.indexPlan)
	p.schema = p.tablePlan.Schema()
	return &p
}

// Init initializes PhysicalIndexMergeReader.
func (p PhysicalIndexMergeReader) Init(ctx PlanContext, offset int) *PhysicalIndexMergeReader {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeIndexMerge, &p, offset)
	if p.tablePlan != nil {
		p.SetStats(p.tablePlan.StatsInfo())
	} else {
		var totalRowCount float64
		for _, partPlan := range p.partialPlans {
			totalRowCount += partPlan.StatsCount()
		}
		p.SetStats(p.partialPlans[0].StatsInfo().ScaleByExpectCnt(totalRowCount))
		p.StatsInfo().StatsVersion = p.partialPlans[0].StatsInfo().StatsVersion
	}
	p.PartialPlans = make([][]PhysicalPlan, 0, len(p.partialPlans))
	for _, partialPlan := range p.partialPlans {
		tempPlans := flattenPushDownPlan(partialPlan)
		p.PartialPlans = append(p.PartialPlans, tempPlans)
	}
	if p.tablePlan != nil {
		p.TablePlans = flattenPushDownPlan(p.tablePlan)
		p.schema = p.tablePlan.Schema()
		p.HandleCols = p.TablePlans[0].(*PhysicalTableScan).HandleCols
	} else {
		switch p.PartialPlans[0][0].(type) {
		case *PhysicalTableScan:
			p.schema = p.PartialPlans[0][0].Schema()
		default:
			is := p.PartialPlans[0][0].(*PhysicalIndexScan)
			p.schema = is.dataSourceSchema
		}
	}
	if p.KeepOrder {
		switch x := p.PartialPlans[0][0].(type) {
		case *PhysicalTableScan:
			p.ByItems = x.ByItems
		case *PhysicalIndexScan:
			p.ByItems = x.ByItems
		}
	}
	return &p
}

func (p *PhysicalTableReader) adjustReadReqType(ctx PlanContext) {
	if p.StoreType == kv.TiFlash {
		_, ok := p.tablePlan.(*PhysicalExchangeSender)
		if ok {
			p.ReadReqType = MPP
			return
		}
		tableScans := p.GetTableScans()
		// When PhysicalTableReader's store type is tiflash, has table scan
		// and all table scans contained are not keepOrder, try to use batch cop.
		if len(tableScans) > 0 {
			for _, tableScan := range tableScans {
				if tableScan.KeepOrder {
					return
				}
			}

			// When allow batch cop is 1, only agg / topN uses batch cop.
			// When allow batch cop is 2, every query uses batch cop.
			switch ctx.GetSessionVars().AllowBatchCop {
			case 1:
				for _, plan := range p.TablePlans {
					switch plan.(type) {
					case *PhysicalHashAgg, *PhysicalStreamAgg, *PhysicalTopN:
						p.ReadReqType = BatchCop
						return
					}
				}
			case 2:
				p.ReadReqType = BatchCop
			}
		}
	}
}

// Init initializes PhysicalTableReader.
func (p PhysicalTableReader) Init(ctx PlanContext, offset int) *PhysicalTableReader {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeTableReader, &p, offset)
	p.ReadReqType = Cop
	if p.tablePlan == nil {
		return &p
	}
	p.TablePlans = flattenPushDownPlan(p.tablePlan)
	p.schema = p.tablePlan.Schema()
	p.adjustReadReqType(ctx)
	if p.ReadReqType == BatchCop || p.ReadReqType == MPP {
		setMppOrBatchCopForTableScan(p.tablePlan)
	}
	return &p
}

// Init initializes PhysicalTableSample.
func (p PhysicalTableSample) Init(ctx PlanContext, offset int) *PhysicalTableSample {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeTableSample, &p, offset)
	p.SetStats(&property.StatsInfo{RowCount: 1})
	return &p
}

// MemoryUsage return the memory usage of PhysicalTableSample
func (p *PhysicalTableSample) MemoryUsage() (sum int64) {
	if p == nil {
		return
	}

	sum = p.physicalSchemaProducer.MemoryUsage() + size.SizeOfInterface + size.SizeOfBool
	if p.TableSampleInfo != nil {
		sum += p.TableSampleInfo.MemoryUsage()
	}
	return
}

// Init initializes PhysicalIndexReader.
func (p PhysicalIndexReader) Init(ctx PlanContext, offset int) *PhysicalIndexReader {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeIndexReader, &p, offset)
	p.SetSchema(nil)
	return &p
}

// Init initializes PhysicalIndexJoin.
func (p PhysicalIndexJoin) Init(ctx PlanContext, stats *property.StatsInfo, offset int, props ...*property.PhysicalProperty) *PhysicalIndexJoin {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeIndexJoin, &p, offset)
	p.childrenReqProps = props
	p.SetStats(stats)
	return &p
}

// Init initializes PhysicalIndexMergeJoin.
func (p PhysicalIndexMergeJoin) Init(ctx PlanContext) *PhysicalIndexMergeJoin {
	p.SetTP(plancodec.TypeIndexMergeJoin)
	p.SetID(int(ctx.GetSessionVars().PlanID.Add(1)))
	p.SetSCtx(ctx)
	p.self = &p
	return &p
}

// Init initializes PhysicalIndexHashJoin.
func (p PhysicalIndexHashJoin) Init(ctx PlanContext) *PhysicalIndexHashJoin {
	p.SetTP(plancodec.TypeIndexHashJoin)
	p.SetID(int(ctx.GetSessionVars().PlanID.Add(1)))
	p.SetSCtx(ctx)
	p.self = &p
	return &p
}

// Init initializes BatchPointGetPlan.
func (p *BatchPointGetPlan) Init(ctx PlanContext, stats *property.StatsInfo, schema *expression.Schema, names []*types.FieldName, offset int) *BatchPointGetPlan {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeBatchPointGet, offset)
	p.schema = schema
	p.names = names
	p.SetStats(stats)
	p.Columns = ExpandVirtualColumn(p.Columns, p.schema, p.TblInfo.Columns)

	var (
		pids   = make([]int64, 0, len(p.IndexValues))
		hasErr bool
		d      types.Datum
	)

	if p.PartitionColPos == GlobalWithoutColumnPos {
		return p
	}

	if p.PartitionExpr != nil {
		if len(p.Handles) > 0 {
			for _, handle := range p.Handles {
				if handle.IsInt() {
					d = types.NewIntDatum(handle.IntValue())
				} else {
					var err error
					_, d, err = codec.DecodeOne(handle.EncodedCol(p.PartitionColPos))
					if err != nil {
						hasErr = true
						break
					}
				}
				pid, err := GetPhysID(p.TblInfo, p.PartitionExpr, p.PartitionColPos, d)
				if err != nil {
					hasErr = true
					break
				}
				pids = append(pids, pid)
			}
		} else {
			for _, idxVals := range p.IndexValues {
				pid, err := GetPhysID(p.TblInfo, p.PartitionExpr, p.PartitionColPos, idxVals[p.PartitionColPos])
				if err != nil {
					hasErr = true
					break
				}
				pids = append(pids, pid)
			}
		}
	}
	if !hasErr {
		p.PartitionIDs = pids
	}
	return p
}

// Init initializes PointGetPlan.
func (p PointGetPlan) Init(ctx PlanContext, stats *property.StatsInfo, offset int, _ ...*property.PhysicalProperty) *PointGetPlan {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypePointGet, offset)
	p.SetStats(stats)
	p.Columns = ExpandVirtualColumn(p.Columns, p.schema, p.TblInfo.Columns)
	return &p
}

// Init only assigns type and context.
func (p PhysicalExchangeSender) Init(ctx PlanContext, stats *property.StatsInfo) *PhysicalExchangeSender {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeExchangeSender, 0)
	p.SetStats(stats)
	return &p
}

// Init only assigns type and context.
func (p PhysicalExchangeReceiver) Init(ctx PlanContext, stats *property.StatsInfo) *PhysicalExchangeReceiver {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeExchangeReceiver, 0)
	p.SetStats(stats)
	return &p
}

func flattenTreePlan(plan PhysicalPlan, plans []PhysicalPlan) []PhysicalPlan {
	plans = append(plans, plan)
	for _, child := range plan.Children() {
		plans = flattenTreePlan(child, plans)
	}
	return plans
}

// flattenPushDownPlan converts a plan tree to a list, whose head is the leaf node like table scan.
func flattenPushDownPlan(p PhysicalPlan) []PhysicalPlan {
	plans := make([]PhysicalPlan, 0, 5)
	plans = flattenTreePlan(p, plans)
	for i := 0; i < len(plans)/2; i++ {
		j := len(plans) - i - 1
		plans[i], plans[j] = plans[j], plans[i]
	}
	return plans
}

// Init only assigns type and context.
func (p LogicalCTE) Init(ctx PlanContext, offset int) *LogicalCTE {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeCTE, &p, offset)
	return &p
}

// Init only assigns type and context.
func (p PhysicalCTE) Init(ctx PlanContext, stats *property.StatsInfo) *PhysicalCTE {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeCTE, &p, 0)
	p.SetStats(stats)
	return &p
}

// Init only assigns type and context.
func (p LogicalCTETable) Init(ctx PlanContext, offset int) *LogicalCTETable {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeCTETable, &p, offset)
	return &p
}

// Init only assigns type and context.
func (p PhysicalCTETable) Init(ctx PlanContext, stats *property.StatsInfo) *PhysicalCTETable {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeCTETable, 0)
	p.SetStats(stats)
	return &p
}

// Init initializes FKCheck.
func (p FKCheck) Init(ctx PlanContext) *FKCheck {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeForeignKeyCheck, &p, 0)
	p.SetStats(&property.StatsInfo{})
	return &p
}

// Init initializes FKCascade
func (p FKCascade) Init(ctx PlanContext) *FKCascade {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeForeignKeyCascade, &p, 0)
	p.SetStats(&property.StatsInfo{})
	return &p
}

// Init initializes LogicalSequence
func (p LogicalSequence) Init(ctx PlanContext, offset int) *LogicalSequence {
	p.baseLogicalPlan = newBaseLogicalPlan(ctx, plancodec.TypeSequence, &p, offset)
	return &p
}

// Init initializes PhysicalSequence
func (p PhysicalSequence) Init(ctx PlanContext, stats *property.StatsInfo, blockOffset int, props ...*property.PhysicalProperty) *PhysicalSequence {
	p.basePhysicalPlan = newBasePhysicalPlan(ctx, plancodec.TypeSequence, &p, blockOffset)
	p.SetStats(stats)
	p.childrenReqProps = props
	return &p
}

// Init initializes ScalarSubqueryEvalCtx
func (p ScalarSubqueryEvalCtx) Init(ctx PlanContext, offset int) *ScalarSubqueryEvalCtx {
	p.Plan = base.NewBasePlan(ctx, plancodec.TypeScalarSubQuery, offset)
	return &p
}
