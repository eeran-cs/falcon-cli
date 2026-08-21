// Manually extracted from cwpp FQL files (fqlmeta could not auto-resolve common.FQLProperty pattern).
// Source: GO-CE/cwpp/internal/services/cwppcontainersecurityapi/gateways/

name: "cwpp"

entities: {
	vulnerability: {
		fql_properties: {
			ai_related:                {type: "string", filterable: true}
			base_os:                   {type: "string", filterable: true}
			cid:                       {type: "string", filterable: true}
			container_id:              {type: "string", filterable: true}
			container_running_status:  {type: "string", filterable: true}
			containers_impacted_range: {type: "string", filterable: true}
			cps_rating:                {type: "string", filterable: true}
			cve_id:                    {type: "string", filterable: true}
			cvss_score:                {type: "string", filterable: true}
			description:               {type: "string", filterable: true}
			exploited_status:          {type: "string", filterable: true}
			exploited_status_name:     {type: "string", filterable: true}
			fix_status:                {type: "string", filterable: true}
			image_digest:              {type: "string", filterable: true}
			image_id:                  {type: "string", filterable: true}
			images_impacted_range:     {type: "string", filterable: true}
			include_base_image_vuln:   {type: "string", filterable: true}
			index_digest:              {type: "string", filterable: true}
			is_zero_day:               {type: "string", filterable: true}
			package_name_version:      {type: "string", filterable: true}
			registry:                  {type: "string", filterable: true}
			remediation_available:     {type: "string", filterable: true}
			repository:                {type: "string", filterable: true}
			severity:                  {type: "string", filterable: true}
			tag:                       {type: "string", filterable: true}
		}
	}

	image: {
		fql_properties: {
			ai_related:               {type: "string", filterable: true}
			ai_vulnerability_count:   {type: "string", filterable: true}
			architecture:             {type: "string", filterable: true}
			base_os:                  {type: "string", filterable: true}
			cid:                      {type: "string", filterable: true}
			container_id:             {type: "string", filterable: true}
			container_running_status: {type: "string", filterable: true}
			cps_rating:               {type: "string", filterable: true}
			crowdstrike_user:         {type: "string", filterable: true}
			cve_id:                   {type: "string", filterable: true}
			detection_count:          {type: "string", filterable: true}
			detection_name:           {type: "string", filterable: true}
			detection_severity:       {type: "string", filterable: true}
			first_seen:               {type: "string", filterable: true}
			image_digest:             {type: "string", filterable: true}
			image_id:                 {type: "string", filterable: true}
			include_base_image_vuln:  {type: "string", filterable: true}
			index_digest:             {type: "string", filterable: true}
			layer_digest:             {type: "string", filterable: true}
			multi_arch:               {type: "string", filterable: true}
			package_name_version:     {type: "string", filterable: true}
			registry:                 {type: "string", filterable: true}
			repository:               {type: "string", filterable: true}
			source:                   {type: "string", filterable: true}
			tag:                      {type: "string", filterable: true}
			vulnerability_count:      {type: "string", filterable: true}
			vulnerability_severity:   {type: "string", filterable: true}
		}
	}

	k8s_asset: {
		fql_properties: {
			access:                      {type: "string", filterable: true}
			agent_id:                    {type: "string", filterable: true}
			agent_status:                {type: "string", filterable: true}
			agent_type:                  {type: "string", filterable: true}
			ai_related:                  {type: "string", filterable: true}
			allow_privilege_escalation:   {type: "string", filterable: true}
			annotations_list:            {type: "string", filterable: true}
			app_name:                    {type: "string", filterable: true}
			cid:                         {type: "string", filterable: true}
			cloud_account_id:            {type: "string", filterable: true}
			cloud_instance_id:           {type: "string", filterable: true}
			cloud_name:                  {type: "string", filterable: true}
			cloud_region:                {type: "string", filterable: true}
			cloud_service:               {type: "string", filterable: true}
			cluster_id:                  {type: "string", filterable: true}
			cluster_name:                {type: "string", filterable: true}
			cluster_status:              {type: "string", filterable: true}
			container_count:             {type: "string", filterable: true}
			container_id:                {type: "string", filterable: true}
			container_image_id:          {type: "string", filterable: true}
			container_name:              {type: "string", filterable: true}
			container_runtime_version:   {type: "string", filterable: true}
			cve_id:                      {type: "string", filterable: true}
			deployment_id:               {type: "string", filterable: true}
			deployment_name:             {type: "string", filterable: true}
			deployment_status:           {type: "string", filterable: true}
			detection_name:              {type: "string", filterable: true}
			first_seen:                  {type: "string", filterable: true}
			hosts:                       {type: "string", filterable: true}
			iar_coverage:                {type: "string", filterable: true}
			iar_last_seen:               {type: "string", filterable: true}
			image_detection_count:       {type: "string", filterable: true}
			image_digest:                {type: "string", filterable: true}
			image_has_been_assessed:     {type: "string", filterable: true}
			image_id:                    {type: "string", filterable: true}
			image_name:                  {type: "string", filterable: true}
			image_registry:              {type: "string", filterable: true}
			image_repository:            {type: "string", filterable: true}
			image_tag:                   {type: "string", filterable: true}
			image_vulnerability_count:   {type: "string", filterable: true}
			insecure_mount_source:       {type: "string", filterable: true}
			insecure_mount_type:         {type: "string", filterable: true}
			insecure_propagation_mode:   {type: "string", filterable: true}
			interactive_mode:            {type: "string", filterable: true}
			ipv4:                        {type: "string", filterable: true}
			ipv6:                        {type: "string", filterable: true}
			kac_agent_id:                {type: "string", filterable: true}
			kpa_last_seen:               {type: "string", filterable: true}
			kubernetes_version:          {type: "string", filterable: true}
			labels:                      {type: "string", filterable: true}
			last_seen:                   {type: "string", filterable: true}
			linux_sensor_coverage:       {type: "string", filterable: true}
			management_status:           {type: "string", filterable: true}
			namespace:                   {type: "string", filterable: true}
			namespace_id:                {type: "string", filterable: true}
			namespace_name:              {type: "string", filterable: true}
			node_count:                  {type: "string", filterable: true}
			node_name:                   {type: "string", filterable: true}
			node_uid:                    {type: "string", filterable: true}
			owner_id:                    {type: "string", filterable: true}
			owner_type:                  {type: "string", filterable: true}
			package_name_version:        {type: "string", filterable: true}
			pod_count:                   {type: "string", filterable: true}
			pod_external_id:             {type: "string", filterable: true}
			pod_id:                      {type: "string", filterable: true}
			pod_name:                    {type: "string", filterable: true}
			port:                        {type: "string", filterable: true}
			privileged:                  {type: "string", filterable: true}
			read_only_root_filesystem:   {type: "string", filterable: true}
			replicaset_id:               {type: "string", filterable: true}
			replicaset_name:             {type: "string", filterable: true}
			resource_status:             {type: "string", filterable: true}
			root_write_access:           {type: "string", filterable: true}
			run_as_root_group:           {type: "string", filterable: true}
			run_as_root_user:            {type: "string", filterable: true}
			running_status:              {type: "string", filterable: true}
			running_time:                {type: "string", filterable: true}
			service_id:                  {type: "string", filterable: true}
			service_name:                {type: "string", filterable: true}
			tags:                        {type: "string", filterable: true}
			vulnerability_name:          {type: "string", filterable: true}
		}
	}

	detection: {
		fql_properties: {
			cid:              {type: "string", filterable: true}
			container_id:     {type: "string", filterable: true}
			detection_type:   {type: "string", filterable: true}
			id:               {type: "string", filterable: true}
			image_digest:     {type: "string", filterable: true}
			image_id:         {type: "string", filterable: true}
			image_registry:   {type: "string", filterable: true}
			image_repository: {type: "string", filterable: true}
			image_tag:        {type: "string", filterable: true}
			name:             {type: "string", filterable: true}
			severity:         {type: "string", filterable: true}
		}
	}

	package: {
		fql_properties: {
			ai_related:          {type: "string", filterable: true}
			cid:                 {type: "string", filterable: true}
			container_id:        {type: "string", filterable: true}
			cveid:               {type: "string", filterable: true}
			fix_status:          {type: "string", filterable: true}
			image_digest:        {type: "string", filterable: true}
			license:             {type: "string", filterable: true}
			package_name_version: {type: "string", filterable: true}
			running_images:      {type: "string", filterable: true}
			severity:            {type: "string", filterable: true}
			type:                {type: "string", filterable: true}
			vulnerability_count: {type: "string", filterable: true}
		}
	}
}
