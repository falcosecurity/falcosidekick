import { Mail, MemoryStick, Plug, ScrollText, Webhook, type LucideIcon } from "lucide-react"

import awss3 from "@/assets/logos/awss3.svg"
import awssns from "@/assets/logos/awssns.svg"
import awssqs from "@/assets/logos/awssqs.svg"
import cloudevents from "@/assets/logos/cloudevents.svg"
import slack from "@/assets/logos/slack.svg"
import teams from "@/assets/logos/teams.svg"

import { DRIVER_LOGOS, type DriverLogoName } from "./driver-logos"

// Marks from the vendors' own kits: Slack (slack.com), Microsoft Teams (Microsoft Fluent product icons),
// Amazon S3, SNS and SQS (AWS Architecture Icons 2026-07-31), CloudEvents (CNCF artwork).
// Trademarks of their owners, used to identify the integrations.
export type DriverIcon =
  | { kind: "logo"; logo: DriverLogoName; official: boolean }
  | { kind: "asset"; src: string; title: string }
  | { kind: "icon"; icon: LucideIcon }

// One entry per v3 driver. `official: false` marks a parent product's mark used for a driver that
// has no mark of its own.
export const DRIVER_ICONS: Record<string, DriverIcon> = {
  alertmanager: { kind: "logo", logo: "prometheus", official: false },
  awss3: { kind: "asset", src: awss3, title: "Amazon S3" },
  awssns: { kind: "asset", src: awssns, title: "Amazon SNS" },
  awssqs: { kind: "asset", src: awssqs, title: "Amazon SQS" },
  cloudevents: { kind: "asset", src: cloudevents, title: "CloudEvents" },
  datadog: { kind: "logo", logo: "datadog", official: true },
  discord: { kind: "logo", logo: "discord", official: true },
  elasticsearch: { kind: "logo", logo: "elasticsearch", official: true },
  gcppubsub: { kind: "logo", logo: "googlepubsub", official: true },
  grafanaoncall: { kind: "logo", logo: "grafana", official: false },
  inmemory: { kind: "icon", icon: MemoryStick },
  kafka: { kind: "logo", logo: "apachekafka", official: true },
  loki: { kind: "logo", logo: "grafana", official: false },
  opsgenie: { kind: "logo", logo: "opsgenie", official: true },
  otlp: { kind: "logo", logo: "opentelemetry", official: true },
  pagerduty: { kind: "logo", logo: "pagerduty", official: true },
  policyreport: { kind: "logo", logo: "kubernetes", official: false },
  redis: { kind: "logo", logo: "redis", official: true },
  slack: { kind: "asset", src: slack, title: "Slack" },
  smtp: { kind: "icon", icon: Mail },
  syslog: { kind: "icon", icon: ScrollText },
  talon: { kind: "logo", logo: "falco", official: false },
  teams: { kind: "asset", src: teams, title: "Microsoft Teams" },
  webhook: { kind: "icon", icon: Webhook },
}

export const DRIVER_NAMES: readonly string[] = Object.keys(DRIVER_ICONS)

const GENERIC: DriverIcon = { kind: "icon", icon: Plug }

export function iconForDriver(driver: string): DriverIcon {
  return DRIVER_ICONS[driver.toLowerCase()] ?? GENERIC
}

export function logoTitle(name: DriverLogoName): string {
  return DRIVER_LOGOS[name].title
}
