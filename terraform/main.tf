terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "5.23.0"
    }
  }
}

# define local variables
locals {
  project                  = "mejuri-project-419216"
  project_id               = "933134782080"
  location                 = "northamerica-northeast2"
  git_app_installation_id  = "49210172"
  git_branch_trigger_regex = "master$"
  github_repo              = "https://github.com/gagankbl/dev-ops-challenge.git"
}

# define input variables
variable "github_token" {
  type = string
}

variable "prod_base_key" {
  type = string
}

variable "iap_client_id" {
  type = string
}

variable "iap_client_secret" {
  type = string
}

variable "account_auth_token" {
  type = string
}

provider "google" {
  project = local.project
}

# create a service account and give it the needed roles to perform any of the tasks defined below
resource "google_service_account" "mejuri_sa" {
  account_id   = "mejuri-sa"
  display_name = "mejuriSA"
}

resource "google_project_iam_member" "sa_binding" {
  for_each = toset([
    "roles/cloudsql.admin",
    "roles/secretmanager.secretAccessor",
    "roles/storage.objectAdmin",
    "roles/storage.admin",
    "roles/run.admin",
    "roles/cloudbuild.builds.editor",
    "roles/logging.logWriter",
    "roles/artifactregistry.writer",
    "roles/iam.serviceAccountUser",
  ])
  role    = each.key
  project = local.project
  member  = "serviceAccount:${google_service_account.mejuri_sa.email}"
}





## SETUP NETWORKING

# create vpc for below services 
resource "google_compute_network" "mejuri_network" {
  name = "mejuri-vpc"
  auto_create_subnetworks = false
}

# create a vpc peering connecting with peering routes to make SQL instance private
resource "google_compute_global_address" "private_ip_address" {
  name          = "mejuri-private-ip-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.mejuri_network.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.mejuri_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

resource "google_compute_network_peering_routes_config" "peering_routes" {
  peering              = google_service_networking_connection.private_vpc_connection.peering
  network              = google_compute_network.mejuri_network.name
  import_custom_routes = true
  export_custom_routes = true
}


# create a subnet and access connector to subnet to allow clour run service to connect to private sql instance
resource "google_vpc_access_connector" "mejuri_vpc_connector" {
  name          = "vpc-access-connector"
  subnet {
    name = google_compute_subnetwork.mejuri_subnet.name
  }
  region        = local.location
}

# enable private google access for the subnet so it can communicate with external google API endpoints
resource "google_compute_subnetwork" "mejuri_subnet" {
  name          = "mejuri-subnet"
  ip_cidr_range = "10.2.0.0/28"
  region        = local.location
  network       = google_compute_network.mejuri_network.id
  private_ip_google_access = true
}





## SETUP DATABASE

# Create a SQL database instance
resource "google_sql_database_instance" "psqldb" {
  name             = "mejuridb"
  database_version = "POSTGRES_11"
  region           = local.location
  root_password    = "postgres"
  # deletion_protection = false
  settings {
    tier = "db-custom-1-3840"

    # this put the database behind a private IP accessible within the VPC
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.mejuri_network.id
      enable_private_path_for_google_cloud_services = true
    }
  }
}

# Create a SQL database within the newly created SQL database instance
resource "google_sql_database" "hello_world_db" {
  name       = "hello_world"
  instance   = google_sql_database_instance.psqldb.name
  project    = google_sql_database_instance.psqldb.project
}

# Create user for the newly created SQL database instance
resource "google_sql_user" "users" {
  name     = "admin"
  instance = google_sql_database_instance.psqldb.name
  password = "admin"
}

# create bucket to store db file
resource "google_storage_bucket" "mejuri_bucket" {
  name          = "mejuri_bucket"
  location      = local.location
  storage_class = "STANDARD"

  uniform_bucket_level_access = true
}

# Upload the db file to bucket
resource "google_storage_bucket_object" "db_file" {
  name         = "database.yml"
  source       = "${path.cwd}/../db/database.sql"
  content_type = "text/yaml"
  bucket       = google_storage_bucket.mejuri_bucket.id
}

# need this to let cloud sql import DB dump from storage bucket
resource "google_project_iam_member" "cloud_sql_sa_binding" {
  role    = "roles/storage.admin"
  project = local.project
  member  = "serviceAccount:${google_sql_database_instance.psqldb.service_account_email_address}"
}

## NOTE additional step here (terraform doesnt seem to support it)
## ALSO run this before creating the cluod run service to avoid any problems
# import the SQL dump from the GCS bucket (uploaded above) into the database
# run this gcloud command separately or manually insert from console (set the user to Admin during import):

# gcloud sql import sql mejuridb gs://mejuri_bucket/database.yml --database=hello_world --user=admin


# add the production base key value to secret manager so Cloud Run can access it
resource "google_secret_manager_secret" "prod_base_key" {
  secret_id = "prod_base_key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "prod_base_key_value" {
  secret      = google_secret_manager_secret.prod_base_key.name
  secret_data = var.prod_base_key
}






## SETUP GITHUB CLOUD BUILD TRIGGER AND CLOUD RUN

# Create a secret containing the Github personal access token for the repo
resource "google_secret_manager_secret" "github_token_secret" {
    secret_id = "github_token"
    replication {
        auto {}
    }
}

resource "google_secret_manager_secret_version" "github_token_secret_value" {
    secret = google_secret_manager_secret.github_token_secret.id
    secret_data = var.github_token
}

# give the cloud build service account the needed role to access the gtthub token secret from secret manager
data "google_iam_policy" "serviceagent_secretAccessor" {
    binding {
        role = "roles/secretmanager.secretAccessor"
        members = ["serviceAccount:service-${local.project_id}@gcp-sa-cloudbuild.iam.gserviceaccount.com"]
    }
}

resource "google_secret_manager_secret_iam_policy" "policy" {
  project = google_secret_manager_secret.github_token_secret.project
  secret_id = google_secret_manager_secret.github_token_secret.secret_id
  policy_data = data.google_iam_policy.serviceagent_secretAccessor.policy_data
}

# Create the GitHub connection
resource "google_cloudbuildv2_connection" "git_connection" {
    project  = local.project
    location = local.location
    name     = "git_connection"

    github_config {
        # this is the installation id of cloud build on the repo being used
        app_installation_id = local.git_app_installation_id
        authorizer_credential {
            oauth_token_secret_version = google_secret_manager_secret_version.github_token_secret_value.id
        }
    }
    depends_on = [google_secret_manager_secret_iam_policy.policy]
}

resource "google_cloudbuildv2_repository" "my_repository" {
      project  = local.project
      location = local.location
      name     = "mejuri-project-repo"
      parent_connection = google_cloudbuildv2_connection.git_connection.name
      remote_uri = local.github_repo
  }

## IMPORTANT: create this at the end after everything else is up and running
# create a cloub build trigger to run the build and deployment pipeline at every push to branch
# the pipeline is defined in cloudbuild.yaml which will:
# 1) build docker image from dockerfile
# 2) push the image to GCR
# 3) deploy the image to cloud run
# 4) also sends logs to a regional GCS bucket in the same project
module "trigger" {
  source      = "memes/cloudbuild/google//modules/github"
  version     = "1.0.0"
  name        = "github-trigger"
  source_repo = "gagankbl/dev-ops-challenge"
  project_id  = local.project
  filename    = "cloudbuild.yaml"
  service_account = google_service_account.mejuri_sa.email
  trigger_config = {
    is_pr_trigger   = false
    branch_regex    = local.git_branch_trigger_regex
    tag_regex       = null
    comment_control = null
  }
}

# create a cloud run service that connects to the SQL instance
# also disable all ingress, only allow through an external loadbalancer
# set scaling policy according to requirements
# expose the docker container as port 8080
# access the production base key from secret manager
# forward 100% traffic right away to every new revision
# enable binary auth
# also connect to vpc access connector to enable connection to private ip of SQL DB
resource "google_cloud_run_v2_service" "rails_service" {
  name     = "mejurirailsservice"
  location = local.location
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  client   = "gcloud"
  client_version = "471.0.0"

  template {
    service_account = google_service_account.mejuri_sa.email
    scaling {
      max_instance_count = 10
      min_instance_count = 1
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.psqldb.connection_name]
      }
    }
    vpc_access{
      connector = google_vpc_access_connector.mejuri_vpc_connector.id
      egress = "ALL_TRAFFIC"
    }

    containers {
      image = "gcr.io/${local.project}/mejuri:latest"
      ports {
        container_port = "8080"
      }
      env {
        name = "SECRET_KEY_BASE"
        value_source {
          secret_key_ref {
            secret = google_secret_manager_secret.prod_base_key.secret_id
            version = "latest"
          }
        }
      }
      volume_mounts {
        name = "cloudsql"
        mount_path = "/cloudsql"
      }
    }
  }
  binary_authorization {
    use_default = true
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
  depends_on = [google_secret_manager_secret_version.prod_base_key_value]
}





# ## SETUP EXTERNAL LOAD BALANCING



# create a self signed ssl cert
resource "google_compute_ssl_certificate" "ssl_cert" {
  name_prefix = "mejuri-cert-"
  description = "self signed ssl cert"
  # generate the below files in the repo home directory using openssl commands
  private_key = file("${path.cwd}/../cert.key")
  certificate = file("${path.cwd}/../cert.crt")

  lifecycle {
    create_before_destroy = true
  }
}

# create a defautl cloud armour security policy to protect against common attacks
resource "google_compute_security_policy" "policy" {
  name        = "mejuri-security-policy"
  description = "security policy"
  type        = "CLOUD_ARMOR"
}

# create the load balancer in front of the Cloud run service
# supply the above created SSL cert
# enable logging and keep CDN disabled for now (cost reasons)
# also apply the cloud armor policy created above
# place the LB behind IAP protection to allow only google authorized accounts to access endpoint
module "lb-http" {
  source  = "terraform-google-modules/lb-http/google//modules/serverless_negs"
  version = "~> 10.0"

  name    = "mejuriexternallb"
  project = local.project

  ssl                             = true
  https_redirect                  = true

  ## this ssl cert points to the self managed one created above
  # ssl_certificates   = [google_compute_ssl_certificate.ssl_cert.self_link]

  ## this ssl cert points to google managed one that I created from console pointing to 
  ## my personal domain: thisisgagan.com
  ## I also created the DNS record for this domain to point to the LB IP
  ssl_certificates   = ["projects/mejuri-project-419216/global/sslCertificates/thisisgagancert"]
  
  security_policy = google_compute_security_policy.policy.self_link
  backends = {
    default = {
      description = null
      groups = [
        {
          group = google_compute_region_network_endpoint_group.serverless_neg.id
        }
      ]
      enable_cdn = false

      iap_config = {
        enable               = true
        oauth2_client_id     = var.iap_client_id
        oauth2_client_secret = var.iap_client_secret
      }
      log_config = {
        enable = true
      }
    }
  }
}

# setup a NEG for the backend service that points to the Cloud run service we want to serve
resource "google_compute_region_network_endpoint_group" "serverless_neg" {
  name                  = "mejruri-serverless-neg"
  network_endpoint_type = "SERVERLESS"
  region                = local.location
  cloud_run {
    service = google_cloud_run_v2_service.rails_service.name
  }
}

# give the IAP service account access to invoke the cloud run service
resource "google_project_iam_member" "cloud_iap_sa_binding" {
  role    = "roles/run.invoker"
  project = local.project
  member  = "serviceAccount:service-${local.project_id}@gcp-sa-iap.iam.gserviceaccount.com"
}






## MONITORING

# create an uptime check for the service where it checks for response code 200 and
# verifies response content of "Hello_world!"
resource "google_monitoring_uptime_check_config" "uptime_check" {
  display_name = "mejuri-https-uptime-check"
  timeout = "10s"

  http_check {
    path = "/hello_world"
    port = "443"
    use_ssl = true
    validate_ssl = true
    mask_headers = true
    headers = {
      "Authorization" = "Bearer ${var.account_auth_token}"
    }
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = local.project
      host = "thisisgagan.com"
    }
  }

  content_matchers {
    content = "Hello World!"
    matcher = "CONTAINS_STRING"
  }
}

# create an alert for when the above uptime check fails for any region
resource "google_monitoring_alert_policy" "uptime_alert_policy" {
  display_name = "Service uptime failure"
  combiner     = "OR"
  conditions {
    display_name = "failure of uptime check for mejuri service"
    condition_threshold {
      filter     = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\" AND metric.labels.check_id=${google_monitoring_uptime_check_config.uptime_check.uptime_check_id}"
      duration   = "60s"
      comparison = "COMPARISON_GT"
      threshold_value = "1"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_NEXT_OLDER"
        group_by_fields = [ "resource.labels.project_id", "resource.labels.host" ]
        cross_series_reducer = "REDUCE_COUNT_FALSE"
      }
    }
    
  }
}

# create an alert for checking when service instance account is approaching limit 
resource "google_monitoring_alert_policy" "instance_count_alert_policy" {
  display_name = "Service instance count high"
  combiner     = "OR"
  conditions {
    display_name = "Instance count is high"
    condition_threshold {
      filter     = "metric.type=\"run.googleapis.com/container/instance_count\" AND resource.type=\"cloud_run_revision\" AND resource.labels.service_name=${google_cloud_run_v2_service.rails_service.name}"
      duration   = "60s"
      comparison = "COMPARISON_GT"
      threshold_value = "8"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
}

# create an alert for when service request latency is high
resource "google_monitoring_alert_policy" "latency_alert_policy" {
  display_name = "Service high latency"
  combiner     = "OR"
  conditions {
    display_name = "Latency is high"
    condition_threshold {
      filter     = "metric.type=\"run.googleapis.com/request_latencies\" AND resource.type=\"cloud_run_revision\" AND resource.labels.service_name=${google_cloud_run_v2_service.rails_service.name}"
      duration   = "60s"
      comparison = "COMPARISON_GT"
      threshold_value = "200"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_PERCENTILE_99"
      }
    }
  }
}


# Once all done the service endpoint can be accessed like so:

## No official domain, and no IAP :
# authenticate gcloud with a service account that has permissions first (the one created above)
# curl -k -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
# https://${LB_IP_ADDRESS}:443/hello_world


## my custom domain, with IAP enabled:
# $OAUTH_CLIENT_ID=933134782080-56vi8k4ttpm6tesci45os65pm23r880t.apps.googleusercontent.com
# curl -k -H "Authorization: Bearer $(gcloud auth print-identity-token --audiences $OAUTH_CLIENT_ID)" \
# https://www.thisisgagan.com/hello_world
