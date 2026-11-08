// Copyright (C) 2026 The Falco Authors
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
//
// SPDX-License-Identifier: Apache-2.0

package output

import "slices"

// Category groups output types in the API and the UI. Every output type picks one; a new kind of
// destination adds a constant here and to Categories.
type Category string

// The categories an output type can pick.
const (
	CategoryAlerting      Category = "alerting"
	CategoryChat          Category = "chat"
	CategoryEmail         Category = "email"
	CategoryLogs          Category = "logs"
	CategoryObservability Category = "observability"
	CategoryQueue         Category = "queue"
	CategoryResponse      Category = "response"
	CategoryStorage       Category = "storage"
	CategoryWebhook       Category = "webhook"
	CategoryOther         Category = "other"
)

// Categories lists every category, in the order the UI shows them.
var Categories = []Category{
	CategoryAlerting,
	CategoryChat,
	CategoryEmail,
	CategoryLogs,
	CategoryObservability,
	CategoryQueue,
	CategoryResponse,
	CategoryStorage,
	CategoryWebhook,
	CategoryOther,
}

// Known reports whether c is one of Categories.
func (c Category) Known() bool {
	return slices.Contains(Categories, c)
}
