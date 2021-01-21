# Save the file as phpchain.tf and replace all occurences of "phpchain" with your actual certificate name (no spaces)

# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------


variable "phpchain_public_key_file_path" {
  description = "Write the PEM-encoded certificate public key to this path (e.g. /etc/tls/vault.crt.pem)."
  default = "tls/phpchain.crt.pem" 
}

variable "phpchain_private_key_file_path" {
  description = "Write the PEM-encoded certificate private key to this path (e.g. /etc/tls/vault.key.pem)."
  default = "tls/phpchain.key.pem" 
}

variable "phpchain_owner" {
  description = "The OS user who should be given ownership over the certificate files."
  default = "sgrosu"
}

# variable "organization_name" {
#   description = "The name of the organization to associate with the certificates (e.g. Acme Co)."
#   default = "StreamLand"
# }

variable "phpchain_common_name" {
  description = "The common name to use in the subject of the certificate (e.g. acme.co cert)."
  default = "streamland.com"
}

variable "phpchain_dns_names" {
  description = "List of DNS names for which the certificate will be valid (e.g. vault.service.consul, foo.example.com)."
  type        = list
  default = [
    "phpchain.streamland.com",
    "phpchain.eu.streamland.com"
  ]
}

# variable "ip_addresses" {
#   description = "List of IP addresses for which the certificate will be valid (e.g. 127.0.0.1)."
#   type        = list
#   default = [
#     "127.0.0.1"
#   ]
# }

variable "phpchain_validity_period_hours" {
  description = "The number of hours after initial issuing that the certificate will become invalid."
  default = "8760"
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------


variable "phpchain_allowed_uses" {
  description = "List of keywords from RFC5280 describing a use that is permitted for the issued certificate. For more info and the list of keywords, see https://www.terraform.io/docs/providers/tls/r/self_signed_cert.html#allowed_uses."
  type        = list

  default = [
    "key_encipherment",
    "digital_signature",
  ]
}

variable "phpchain_permissions" {
  description = "The Unix file permission to assign to the cert files (e.g. 0600)."
  default     = "0600"
}

variable "phpchain_private_key_algorithm" {
  description = "The name of the algorithm to use for private keys. Must be one of: RSA or ECDSA."
  default     = "RSA"
}

variable "phpchain_private_key_ecdsa_curve" {
  description = "The name of the elliptic curve to use. Should only be used if var.private_key_algorithm is ECDSA. Must be one of P224, P256, P384 or P521."
  default     = "P256"
}

variable "phpchain_private_key_rsa_bits" {
  description = "The size of the generated RSA key in bits. Should only be used if var.private_key_algorithm is RSA."
  default     = "2048"
}


# ---------------------------------------------------------------------------------------------------------------------
# CREATE THE TLS CERTIFICATE 
# ---------------------------------------------------------------------------------------------------------------------

resource "tls_private_key" "phpchain" {
  algorithm   = "${var.private_key_algorithm}"
  ecdsa_curve = "${var.private_key_ecdsa_curve}"
  rsa_bits    = "${var.private_key_rsa_bits}"

  # Store the certificate's private key in a file.
  provisioner "local-exec" {
    command = "echo '${tls_private_key.phpchain.private_key_pem}' > '${var.phpchain_private_key_file_path}' && chmod ${var.phpchain_permissions} '${var.phpchain_private_key_file_path}' && chown ${var.phpchain_owner} '${var.phpchain_private_key_file_path}'"
  }
}

resource "tls_cert_request" "phpchain" {
  key_algorithm   = "${tls_private_key.phpchain.algorithm}"
  private_key_pem = "${tls_private_key.phpchain.private_key_pem}"

  dns_names    = var.dns_names
  #ip_addresses = ["${var.ip_addresses}"]

  subject {
    common_name  = "${var.phpchain_common_name}"
    organization = "${var.organization_name}"
  }
}

resource "tls_locally_signed_cert" "phpchain" {
  cert_request_pem = "${tls_cert_request.phpchain.cert_request_pem}"

  ca_key_algorithm   = "${tls_private_key.ca.algorithm}"
  ca_private_key_pem = "${tls_private_key.ca.private_key_pem}"
  ca_cert_pem        = "${tls_self_signed_cert.ca.cert_pem}"

  validity_period_hours = "${var.phpchain_validity_period_hours}"
  allowed_uses          = var.phpchain_allowed_uses

  # Store the certificate's public key in a file.
  provisioner "local-exec" {
    command = "echo '${tls_locally_signed_cert.phpchain.cert_pem}' > '${var.phpchain_public_key_file_path}' && chmod ${var.phpchain_permissions} '${var.phpchain_public_key_file_path}' && chown ${var.phpchain_owner} '${var.phpchain_public_key_file_path}'"
  }
}