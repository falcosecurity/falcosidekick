import { Link } from "react-router"

import { PageHeader } from "@/components/common/page-header"
import { EmptyState } from "@/components/common/empty-state"
import { Button } from "@/components/ui/button"

export function NotFoundPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Not found" description="The route you requested does not exist." />
      <EmptyState
        title="404"
        description="Follow the sidebar back to a valid view."
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/">Go to dashboard</Link>
          </Button>
        }
      />
    </div>
  )
}

export default NotFoundPage
