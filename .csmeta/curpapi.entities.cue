// Manually extracted from curpapi/internal/domain/fql_const.go
// Source: GO-CE/curpapi

name: "curpapi"

entities: {
	cloud_risk: {
		fql_properties: {
			account_id:        {type: "string", filterable: true}
			account_name:      {type: "string", filterable: true}
			adversary:         {type: "string", filterable: true}
			asset_gcrn:        {type: "string", filterable: true}
			asset_id:          {type: "string", filterable: true}
			asset_name:        {type: "string", filterable: true}
			asset_region:      {type: "string", filterable: true}
			asset_type:        {type: "string", filterable: true}
			cloud_group:       {type: "string", filterable: true}
			cloud_provider:    {type: "string", filterable: true}
			first_seen:        {type: "string", filterable: true}
			last_seen:         {type: "string", filterable: true}
			resolved_at:       {type: "string", filterable: true}
			risk_factor:       {type: "string", filterable: true}
			rule_id:           {type: "string", filterable: true}
			rule_name:         {type: "string", filterable: true}
			score:             {type: "string", filterable: true}
			service_category:  {type: "string", filterable: true}
			severity:          {type: "string", filterable: true}
			status:            {type: "string", filterable: true}
			suppressed_by:     {type: "string", filterable: true}
			suppressed_reason: {type: "string", filterable: true}
			tags:              {type: "string", filterable: true}
			threat_actors:     {type: "string", filterable: true}
		}
	}

	logics: {
		fql_properties: {
			alias:             {type: "string", filterable: true}
			asset_types:       {type: "string", filterable: true}
			category:          {type: "string", filterable: true}
			description:       {type: "string", filterable: true}
			disabled:          {type: "string", filterable: true, enum: ["true", "false"]}
			native_policy:     {type: "string", filterable: true}
			policy_version:    {type: "string", filterable: true}
			public:            {type: "string", filterable: true}
			rego_policy:       {type: "string", filterable: true}
			rego_value_filter: {type: "string", filterable: true}
			resource_id:       {type: "string", filterable: true}
		}
	}
}
