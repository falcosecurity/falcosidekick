import { PageHeader } from "@/components/common/page-header"
import { CounterCards } from "@/components/dashboard/counter-cards"
import { DistributionChart } from "@/components/dashboard/distribution-chart"
import { OutputStatusGrid } from "@/components/dashboard/output-status-grid"
import { SourcePieChart } from "@/components/dashboard/source-pie-chart"
import { TimelineChart } from "@/components/dashboard/timeline-chart"

export function DashboardPage() {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="Dashboard"
        description="Event volume by priority, top rules and sources, and live output health for the last 24 hours."
      />
      <div className="mt-4 flex flex-1 flex-col gap-6 overflow-auto pr-1">
        <CounterCards />
        <TimelineChart />
        <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
          <DistributionChart title="Top rules" groupby="rule" />
          <SourcePieChart title="Sources" groupby="source" />
        </div>
        <OutputStatusGrid />
      </div>
    </div>
  )
}

export default DashboardPage
