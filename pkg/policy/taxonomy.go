package policy

// Mutability indicates whether a command reads, writes, or operates locally.
type Mutability string

const (
	// MutabilityRead indicates the command only reads data from the API.
	MutabilityRead Mutability = "read"
	// MutabilityWrite indicates the command modifies data via the API.
	MutabilityWrite Mutability = "write"
	// MutabilityLocal indicates the command operates locally without API calls.
	MutabilityLocal Mutability = "local"
)

// Group identifies the functional area a command belongs to.
type Group string

const (
	GroupAuth          Group = "auth"
	GroupCompute       Group = "compute"
	GroupConfig        Group = "config"
	GroupConfigStore   Group = "configstore"
	GroupDashboard     Group = "dashboard"
	GroupDomain        Group = "domain"
	GroupIP            Group = "ip"
	GroupKVStore       Group = "kvstore"
	GroupLogging       Group = "logging"
	GroupLogtail       Group = "logtail"
	GroupNGWAF         Group = "ngwaf"
	GroupObjectStorage Group = "objectstorage"
	GroupPOP           Group = "pop"
	GroupProducts      Group = "products"
	GroupSecretStore   Group = "secretstore"
	GroupService       Group = "service"
	GroupStats         Group = "stats"
	GroupTLS           Group = "tls"
	GroupTools         Group = "tools"
	GroupUser          Group = "user"
)

// CommandMeta holds the policy metadata for a single CLI command.
type CommandMeta struct {
	Group      Group
	Mutability Mutability
}

// Taxonomy maps command full names (e.g. "service create") to their metadata.
// Commands not present in this map are treated as unrestricted.
var Taxonomy = map[string]CommandMeta{
	// --- auth ---
	"auth login":      {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth add":        {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth use":        {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth list":       {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth show":       {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth delete":     {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth policy set":  {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth policy list": {Group: GroupAuth, Mutability: MutabilityLocal},
	"auth policy show": {Group: GroupAuth, Mutability: MutabilityLocal},

	// --- compute ---
	"compute build":             {Group: GroupCompute, Mutability: MutabilityLocal},
	"compute deploy":            {Group: GroupCompute, Mutability: MutabilityWrite},
	"compute hash-files":        {Group: GroupCompute, Mutability: MutabilityLocal},
	"compute init":              {Group: GroupCompute, Mutability: MutabilityLocal}, // NOTE: --from <service-id> performs an API read; token gating is handled in commandRequiresToken but policy check sees this as local
	"compute metadata":          {Group: GroupCompute, Mutability: MutabilityLocal},
	"compute pack":              {Group: GroupCompute, Mutability: MutabilityLocal},
	"compute publish":           {Group: GroupCompute, Mutability: MutabilityWrite},
	"compute serve":             {Group: GroupCompute, Mutability: MutabilityLocal},
	"compute update":            {Group: GroupCompute, Mutability: MutabilityWrite},
	"compute validate":          {Group: GroupCompute, Mutability: MutabilityLocal},
	"compute acl create":        {Group: GroupCompute, Mutability: MutabilityWrite},
	"compute acl delete":        {Group: GroupCompute, Mutability: MutabilityWrite},
	"compute acl describe":      {Group: GroupCompute, Mutability: MutabilityRead},
	"compute acl list":          {Group: GroupCompute, Mutability: MutabilityRead},
	"compute acl update":        {Group: GroupCompute, Mutability: MutabilityWrite},
	"compute acl lookup":        {Group: GroupCompute, Mutability: MutabilityRead},
	"compute acl list-entries":  {Group: GroupCompute, Mutability: MutabilityRead},

	// --- config ---
	"config": {Group: GroupConfig, Mutability: MutabilityLocal},

	// --- configstore ---
	"config-store create":        {Group: GroupConfigStore, Mutability: MutabilityWrite},
	"config-store delete":        {Group: GroupConfigStore, Mutability: MutabilityWrite},
	"config-store describe":      {Group: GroupConfigStore, Mutability: MutabilityRead},
	"config-store list":          {Group: GroupConfigStore, Mutability: MutabilityRead},
	"config-store list-services": {Group: GroupConfigStore, Mutability: MutabilityRead},
	"config-store update":        {Group: GroupConfigStore, Mutability: MutabilityWrite},
	"config-store-entry create":  {Group: GroupConfigStore, Mutability: MutabilityWrite},
	"config-store-entry delete":  {Group: GroupConfigStore, Mutability: MutabilityWrite},
	"config-store-entry describe": {Group: GroupConfigStore, Mutability: MutabilityRead},
	"config-store-entry list":    {Group: GroupConfigStore, Mutability: MutabilityRead},
	"config-store-entry update":  {Group: GroupConfigStore, Mutability: MutabilityWrite},

	// --- dashboard ---
	"dashboard create":        {Group: GroupDashboard, Mutability: MutabilityWrite},
	"dashboard delete":        {Group: GroupDashboard, Mutability: MutabilityWrite},
	"dashboard describe":      {Group: GroupDashboard, Mutability: MutabilityRead},
	"dashboard list":          {Group: GroupDashboard, Mutability: MutabilityRead},
	"dashboard update":        {Group: GroupDashboard, Mutability: MutabilityWrite},
	"dashboard item create":   {Group: GroupDashboard, Mutability: MutabilityWrite},
	"dashboard item delete":   {Group: GroupDashboard, Mutability: MutabilityWrite},
	"dashboard item describe": {Group: GroupDashboard, Mutability: MutabilityRead},
	"dashboard item update":   {Group: GroupDashboard, Mutability: MutabilityWrite},

	// --- domain ---
	"domain create":   {Group: GroupDomain, Mutability: MutabilityWrite},
	"domain delete":   {Group: GroupDomain, Mutability: MutabilityWrite},
	"domain describe": {Group: GroupDomain, Mutability: MutabilityRead},
	"domain list":     {Group: GroupDomain, Mutability: MutabilityRead},
	"domain update":   {Group: GroupDomain, Mutability: MutabilityWrite},

	// --- ip ---
	"ip-list": {Group: GroupIP, Mutability: MutabilityRead},

	// --- kvstore ---
	"kv-store create":       {Group: GroupKVStore, Mutability: MutabilityWrite},
	"kv-store delete":       {Group: GroupKVStore, Mutability: MutabilityWrite},
	"kv-store describe":     {Group: GroupKVStore, Mutability: MutabilityRead},
	"kv-store list":         {Group: GroupKVStore, Mutability: MutabilityRead},
	"kv-store-entry create":   {Group: GroupKVStore, Mutability: MutabilityWrite},
	"kv-store-entry delete":   {Group: GroupKVStore, Mutability: MutabilityWrite},
	"kv-store-entry describe": {Group: GroupKVStore, Mutability: MutabilityRead},
	"kv-store-entry get":      {Group: GroupKVStore, Mutability: MutabilityRead},
	"kv-store-entry list":     {Group: GroupKVStore, Mutability: MutabilityRead},

	// --- logtail ---
	"log-tail": {Group: GroupLogtail, Mutability: MutabilityRead},

	// --- objectstorage ---
	"object-storage access-keys create": {Group: GroupObjectStorage, Mutability: MutabilityWrite},
	"object-storage access-keys delete": {Group: GroupObjectStorage, Mutability: MutabilityWrite},
	"object-storage access-keys get":    {Group: GroupObjectStorage, Mutability: MutabilityRead},
	"object-storage access-keys list":   {Group: GroupObjectStorage, Mutability: MutabilityRead},

	// --- pop ---
	"pops": {Group: GroupPOP, Mutability: MutabilityRead},

	// --- products ---
	"products": {Group: GroupProducts, Mutability: MutabilityRead},

	// --- secretstore ---
	"secret-store create":       {Group: GroupSecretStore, Mutability: MutabilityWrite},
	"secret-store delete":       {Group: GroupSecretStore, Mutability: MutabilityWrite},
	"secret-store describe":     {Group: GroupSecretStore, Mutability: MutabilityRead},
	"secret-store list":         {Group: GroupSecretStore, Mutability: MutabilityRead},
	"secret-store-entry create":   {Group: GroupSecretStore, Mutability: MutabilityWrite},
	"secret-store-entry delete":   {Group: GroupSecretStore, Mutability: MutabilityWrite},
	"secret-store-entry describe": {Group: GroupSecretStore, Mutability: MutabilityRead},
	"secret-store-entry list":     {Group: GroupSecretStore, Mutability: MutabilityRead},

	// --- service ---
	"service create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service describe": {Group: GroupService, Mutability: MutabilityRead},
	"service list":     {Group: GroupService, Mutability: MutabilityRead},
	"service search":   {Group: GroupService, Mutability: MutabilityRead},
	"service update":   {Group: GroupService, Mutability: MutabilityWrite},
	"service purge":    {Group: GroupService, Mutability: MutabilityWrite},

	// --- service acl ---
	"service acl create":        {Group: GroupService, Mutability: MutabilityWrite},
	"service acl delete":        {Group: GroupService, Mutability: MutabilityWrite},
	"service acl describe":      {Group: GroupService, Mutability: MutabilityRead},
	"service acl list":          {Group: GroupService, Mutability: MutabilityRead},
	"service acl update":        {Group: GroupService, Mutability: MutabilityWrite},
	"service acl-entry create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service acl-entry delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service acl-entry describe": {Group: GroupService, Mutability: MutabilityRead},
	"service acl-entry list":     {Group: GroupService, Mutability: MutabilityRead},
	"service acl-entry update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service alert ---
	"service alert create":       {Group: GroupService, Mutability: MutabilityWrite},
	"service alert delete":       {Group: GroupService, Mutability: MutabilityWrite},
	"service alert describe":     {Group: GroupService, Mutability: MutabilityRead},
	"service alert list":         {Group: GroupService, Mutability: MutabilityRead},
	"service alert list-history": {Group: GroupService, Mutability: MutabilityRead},
	"service alert update":       {Group: GroupService, Mutability: MutabilityWrite},

	// --- service auth ---
	"service auth create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service auth delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service auth describe": {Group: GroupService, Mutability: MutabilityRead},
	"service auth list":     {Group: GroupService, Mutability: MutabilityRead},
	"service auth update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service backend ---
	"service backend create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service backend delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service backend describe": {Group: GroupService, Mutability: MutabilityRead},
	"service backend list":     {Group: GroupService, Mutability: MutabilityRead},
	"service backend update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service dictionary ---
	"service dictionary create":        {Group: GroupService, Mutability: MutabilityWrite},
	"service dictionary delete":        {Group: GroupService, Mutability: MutabilityWrite},
	"service dictionary describe":      {Group: GroupService, Mutability: MutabilityRead},
	"service dictionary list":          {Group: GroupService, Mutability: MutabilityRead},
	"service dictionary update":        {Group: GroupService, Mutability: MutabilityWrite},
	"service dictionary-entry create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service dictionary-entry delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service dictionary-entry describe": {Group: GroupService, Mutability: MutabilityRead},
	"service dictionary-entry list":     {Group: GroupService, Mutability: MutabilityRead},
	"service dictionary-entry update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service domain ---
	"service domain create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service domain delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service domain describe": {Group: GroupService, Mutability: MutabilityRead},
	"service domain list":     {Group: GroupService, Mutability: MutabilityRead},
	"service domain update":   {Group: GroupService, Mutability: MutabilityWrite},
	"service domain validate": {Group: GroupService, Mutability: MutabilityRead},

	// --- service healthcheck ---
	"service healthcheck create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service healthcheck delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service healthcheck describe": {Group: GroupService, Mutability: MutabilityRead},
	"service healthcheck list":     {Group: GroupService, Mutability: MutabilityRead},
	"service healthcheck update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service imageoptimizer ---
	"service imageoptimizer get":    {Group: GroupService, Mutability: MutabilityRead},
	"service imageoptimizer update": {Group: GroupService, Mutability: MutabilityWrite},

	// --- service rate-limit ---
	"service rate-limit create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service rate-limit delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service rate-limit describe": {Group: GroupService, Mutability: MutabilityRead},
	"service rate-limit list":     {Group: GroupService, Mutability: MutabilityRead},
	"service rate-limit update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service resource-link ---
	"service resource-link create":   {Group: GroupService, Mutability: MutabilityWrite},
	"service resource-link delete":   {Group: GroupService, Mutability: MutabilityWrite},
	"service resource-link describe": {Group: GroupService, Mutability: MutabilityRead},
	"service resource-link list":     {Group: GroupService, Mutability: MutabilityRead},
	"service resource-link update":   {Group: GroupService, Mutability: MutabilityWrite},

	// --- service version ---
	"service version activate":   {Group: GroupService, Mutability: MutabilityWrite},
	"service version clone":      {Group: GroupService, Mutability: MutabilityWrite},
	"service version deactivate": {Group: GroupService, Mutability: MutabilityWrite},
	"service version list":       {Group: GroupService, Mutability: MutabilityRead},
	"service version lock":       {Group: GroupService, Mutability: MutabilityWrite},
	"service version stage":      {Group: GroupService, Mutability: MutabilityWrite},
	"service version unstage":    {Group: GroupService, Mutability: MutabilityWrite},
	"service version update":     {Group: GroupService, Mutability: MutabilityWrite},

	// --- service vcl ---
	"service vcl describe":            {Group: GroupService, Mutability: MutabilityRead},
	"service vcl condition create":    {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl condition delete":    {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl condition describe":  {Group: GroupService, Mutability: MutabilityRead},
	"service vcl condition list":      {Group: GroupService, Mutability: MutabilityRead},
	"service vcl condition update":    {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl custom create":       {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl custom delete":       {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl custom describe":     {Group: GroupService, Mutability: MutabilityRead},
	"service vcl custom list":         {Group: GroupService, Mutability: MutabilityRead},
	"service vcl custom update":       {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl snippet create":      {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl snippet delete":      {Group: GroupService, Mutability: MutabilityWrite},
	"service vcl snippet describe":    {Group: GroupService, Mutability: MutabilityRead},
	"service vcl snippet list":        {Group: GroupService, Mutability: MutabilityRead},
	"service vcl snippet update":      {Group: GroupService, Mutability: MutabilityWrite},

	// --- service logging (27 endpoints x 5 operations) ---
	// Each logging endpoint: create=write, delete=write, describe=read, list=read, update=write
	// azureblob
	"service logging azureblob create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging azureblob delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging azureblob describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging azureblob list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging azureblob update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// bigquery
	"service logging bigquery create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging bigquery delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging bigquery describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging bigquery list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging bigquery update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// cloudfiles
	"service logging cloudfiles create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging cloudfiles delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging cloudfiles describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging cloudfiles list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging cloudfiles update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// datadog
	"service logging datadog create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging datadog delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging datadog describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging datadog list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging datadog update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// digitalocean
	"service logging digitalocean create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging digitalocean delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging digitalocean describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging digitalocean list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging digitalocean update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// elasticsearch
	"service logging elasticsearch create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging elasticsearch delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging elasticsearch describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging elasticsearch list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging elasticsearch update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// ftp
	"service logging ftp create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging ftp delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging ftp describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging ftp list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging ftp update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// gcs
	"service logging gcs create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging gcs delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging gcs describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging gcs list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging gcs update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// googlepubsub
	"service logging googlepubsub create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging googlepubsub delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging googlepubsub describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging googlepubsub list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging googlepubsub update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// grafanacloudlogs
	"service logging grafanacloudlogs create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging grafanacloudlogs delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging grafanacloudlogs describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging grafanacloudlogs list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging grafanacloudlogs update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// heroku
	"service logging heroku create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging heroku delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging heroku describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging heroku list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging heroku update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// honeycomb
	"service logging honeycomb create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging honeycomb delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging honeycomb describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging honeycomb list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging honeycomb update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// https
	"service logging https create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging https delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging https describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging https list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging https update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// kafka
	"service logging kafka create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging kafka delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging kafka describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging kafka list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging kafka update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// kinesis
	"service logging kinesis create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging kinesis delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging kinesis describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging kinesis list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging kinesis update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// loggly
	"service logging loggly create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging loggly delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging loggly describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging loggly list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging loggly update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// logshuttle
	"service logging logshuttle create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging logshuttle delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging logshuttle describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging logshuttle list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging logshuttle update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// newrelic
	"service logging newrelic create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging newrelic delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging newrelic describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging newrelic list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging newrelic update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// newrelicotlp
	"service logging newrelicotlp create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging newrelicotlp delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging newrelicotlp describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging newrelicotlp list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging newrelicotlp update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// openstack
	"service logging openstack create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging openstack delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging openstack describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging openstack list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging openstack update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// papertrail
	"service logging papertrail create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging papertrail delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging papertrail describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging papertrail list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging papertrail update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// s3
	"service logging s3 create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging s3 delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging s3 describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging s3 list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging s3 update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// scalyr
	"service logging scalyr create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging scalyr delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging scalyr describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging scalyr list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging scalyr update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// sftp
	"service logging sftp create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging sftp delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging sftp describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging sftp list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging sftp update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// splunk
	"service logging splunk create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging splunk delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging splunk describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging splunk list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging splunk update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// sumologic
	"service logging sumologic create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging sumologic delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging sumologic describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging sumologic list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging sumologic update":   {Group: GroupLogging, Mutability: MutabilityWrite},
	// syslog
	"service logging syslog create":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging syslog delete":   {Group: GroupLogging, Mutability: MutabilityWrite},
	"service logging syslog describe": {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging syslog list":     {Group: GroupLogging, Mutability: MutabilityRead},
	"service logging syslog update":   {Group: GroupLogging, Mutability: MutabilityWrite},

	// --- stats ---
	"stats historical": {Group: GroupStats, Mutability: MutabilityRead},
	"stats realtime":   {Group: GroupStats, Mutability: MutabilityRead},
	"stats regions":    {Group: GroupStats, Mutability: MutabilityRead},

	// --- tls-config ---
	"tls-config describe": {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-config list":     {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-config update":   {Group: GroupTLS, Mutability: MutabilityWrite},

	// --- tls-custom ---
	"tls-custom activation create":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom activation delete":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom activation describe": {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-custom activation list":     {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-custom activation update":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom certificate create":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom certificate delete":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom certificate describe": {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-custom certificate list":     {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-custom certificate update":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom domain list":          {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-custom private-key create":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom private-key delete":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-custom private-key describe": {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-custom private-key list":     {Group: GroupTLS, Mutability: MutabilityRead},

	// --- tls-platform ---
	"tls-platform create":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-platform delete":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-platform describe": {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-platform list":     {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-platform update":   {Group: GroupTLS, Mutability: MutabilityWrite},

	// --- tls-subscription ---
	"tls-subscription create":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-subscription delete":   {Group: GroupTLS, Mutability: MutabilityWrite},
	"tls-subscription describe": {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-subscription list":     {Group: GroupTLS, Mutability: MutabilityRead},
	"tls-subscription update":   {Group: GroupTLS, Mutability: MutabilityWrite},

	// --- tools ---
	"tools domain status":      {Group: GroupTools, Mutability: MutabilityRead},
	"tools domain suggestions": {Group: GroupTools, Mutability: MutabilityRead},

	// --- user ---
	"user create":   {Group: GroupUser, Mutability: MutabilityWrite},
	"user delete":   {Group: GroupUser, Mutability: MutabilityWrite},
	"user describe": {Group: GroupUser, Mutability: MutabilityRead},
	"user list":     {Group: GroupUser, Mutability: MutabilityRead},
	"user update":   {Group: GroupUser, Mutability: MutabilityWrite},

	// --- other ---
	"install":        {Group: GroupConfig, Mutability: MutabilityLocal},
	"update":         {Group: GroupConfig, Mutability: MutabilityLocal},
	"version":        {Group: GroupConfig, Mutability: MutabilityLocal},
	"whoami":         {Group: GroupUser, Mutability: MutabilityRead},
	"shellcomplete":  {Group: GroupConfig, Mutability: MutabilityLocal},
}

// LookupMutability returns the mutability for a command name.
// If the command is not in the taxonomy, it returns MutabilityWrite as the safe default.
func LookupMutability(commandName string) Mutability {
	if meta, ok := Taxonomy[commandName]; ok {
		return meta.Mutability
	}
	return MutabilityWrite // unknown commands default to write for safety
}

// LookupGroup returns the group for a command name.
func LookupGroup(commandName string) (Group, bool) {
	if meta, ok := Taxonomy[commandName]; ok {
		return meta.Group, true
	}
	return "", false
}
