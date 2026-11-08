import { PageHeader } from "@/components/common/page-header"
import { EmptyState } from "@/components/common/empty-state"

interface PlaceholderPageProps {
  title: string
  description: string
  message: string
}

export function PlaceholderPage({ title, description, message }: PlaceholderPageProps) {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={title} description={description} />
      <EmptyState
        title="Not yet wired"
        description={message}
      />
    </div>
  )
}
