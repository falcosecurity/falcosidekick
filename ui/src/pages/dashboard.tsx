import { PageHeader } from "@/components/common/page-header"
import { AttentionCard } from "@/components/dashboard/attention"
import { DeliveryCard } from "@/components/dashboard/delivery-card"
import { KpiCards } from "@/components/dashboard/kpi-cards"
import { SeverityCard } from "@/components/dashboard/severity-card"
import { TimelineChart } from "@/components/dashboard/timeline-chart"
import { TopCard } from "@/components/dashboard/top-card"

export function DashboardPage() {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Dashboard" description="What needs attention now, delivery to the outputs and event volume by severity." />
      <div className="mt-4 flex flex-1 flex-col gap-4 overflow-auto pr-1 pb-6">
        <div className="grid gap-4 xl:grid-cols-2 *:min-w-0">
          <KpiCards />
          {/* On narrow screens what needs attention comes before the figures. */}
          <AttentionCard className="order-first xl:order-none" />
        </div>
        <div className="grid gap-4 xl:grid-cols-3 *:min-w-0">
          <TimelineChart className="xl:col-span-2" />
          <SeverityCard />
        </div>
        <div className="grid gap-4 xl:grid-cols-2 *:min-w-0">
          <DeliveryCard />
          <TopCard />
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
