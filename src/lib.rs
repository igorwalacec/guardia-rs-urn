use dotenv::dotenv;
use std::env;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UrnBuilderError {
    #[error("Invalid product: {0}")]
    InvalidProduct(String),

    #[error("Invalid cloud provider: {0}")]
    InvalidCloudProvider(String),

    #[error("Invalid region: {0}. Valid regions are: {1}")]
    InvalidRegion(String, String),

    #[error("Missing required field: {0}")]
    MissingRequiredField(String),

    #[error("Invalid rail: {0}")]
    InvalidRail(String),

    #[error("Invalid provider: {0}")]
    InvalidProvider(String),

    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),
}

#[derive(Debug)]
pub struct GuardiaUrn {
    organization_id: String,
    tenant_id: String,
    cloud_provider: String,
    region: String,
    product: String,
    rail: String,
    provider: String,
    protocol: String,
    entity_type: String,
    entity_id: String,
}

impl fmt::Display for GuardiaUrn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = vec![
            format!("urn:guardia:org:{}", self.organization_id),
            format!("tenant:{}", self.tenant_id),
            self.product.clone(),
            self.entity_type.clone(),
            self.entity_id.clone(),
        ];

        if !&self.cloud_provider.trim().is_empty() && !&self.region.trim().is_empty() {
            parts.insert(2, format!("[{}:{}]", self.cloud_provider, self.region));
        }
        if !&self.rail.trim().is_empty() {
            parts.insert(3, self.rail.clone());
        }
        if !&self.provider.trim().is_empty() {
            parts.insert(4, self.provider.clone());
        }
        if !&self.protocol.trim().is_empty() {
            parts.insert(5, self.protocol.clone());
        }

        write!(f, "{}", parts.join(":"))
    }
}

pub struct UrnBuilder {
    organization_id: String,
    tenant_id: String,
    cloud_provider: String,
    region: String,
    product: String,
    rail: String,
    provider: String,
    protocol: String,
    entity_type: String,
    entity_id: String,
}

impl UrnBuilder {
    pub fn new() -> Self {
        Self {
            organization_id: String::new(),
            tenant_id: String::new(),
            cloud_provider: String::new(),
            region: String::new(),
            product: String::new(),
            rail: String::new(),
            provider: String::new(),
            protocol: String::new(),
            entity_type: String::new(),
            entity_id: String::new(),
        }
    }

    pub fn with_organization_id(mut self, organization_id: &str) -> Self {
        self.organization_id = organization_id.to_string();
        self
    }

    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = tenant_id.to_string();
        self
    }

    pub fn with_cloud_provider(mut self, cloud_provider: &str) -> Self {
        self.cloud_provider = cloud_provider.to_string();
        self
    }

    pub fn with_region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn with_product(mut self, product: &str) -> Self {
        self.product = product.to_string();
        self
    }

    pub fn with_rail(mut self, rail: &str) -> Self {
        self.rail = rail.to_string();
        self
    }

    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = protocol.to_string();
        self
    }

    pub fn with_provider(mut self, provider: &str) -> Self {
        self.provider = provider.to_string();
        self
    }

    pub fn with_entity_type(mut self, entity_type: &str) -> Self {
        self.entity_type = entity_type.to_string();
        self
    }

    pub fn with_entity_id(mut self, entity_id: &str) -> Self {
        self.entity_id = entity_id.to_string();
        self
    }

    fn validate_required_field(field_value: &str, field_name: &str) -> Result<(), UrnBuilderError> {
        if field_value.is_empty() {
            Err(UrnBuilderError::MissingRequiredField(field_name.into()))
        } else {
            Ok(())
        }
    }

    fn validate_product(&self) -> Result<(), UrnBuilderError> {
        let valid_products = ["lke", "base", "tms", "psa", "bsa", "dwa"];
        if valid_products.contains(&self.product.as_str()) {
            Ok(())
        } else {
            Err(UrnBuilderError::InvalidProduct(self.product.clone()))
        }
    }

    fn validate_cloud_provider(&self) -> Result<(), UrnBuilderError> {
        if &self.cloud_provider == "aws" {
            Ok(())
        } else {
            Err(UrnBuilderError::InvalidCloudProvider(
                self.cloud_provider.clone(),
            ))
        }
    }

    fn validate_region(&self) -> Result<(), UrnBuilderError> {
        let valid_regions = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-north-1",
            "eu-south-1",
            "eu-central-1",
        ];
        if valid_regions.contains(&self.region.as_str()) {
            Ok(())
        } else {
            Err(UrnBuilderError::InvalidRegion(
                self.region.clone(),
                valid_regions.join(", "),
            ))
        }
    }

    fn validate_rail(&self) -> Result<(), UrnBuilderError> {
        let valid_rails = ["p2p", "pix"];
        if valid_rails.contains(&self.rail.as_str()) {
            Ok(())
        } else {
            Err(UrnBuilderError::InvalidRail(self.rail.clone()))
        }
    }

    fn validate_provider(&self) -> Result<(), UrnBuilderError> {
        let valid_providers = ["guardia", "pix"];
        if valid_providers.contains(&self.provider.as_str()) {
            Ok(())
        } else {
            Err(UrnBuilderError::InvalidProvider(self.provider.clone()))
        }
    }

    fn validate_protocol(&self) -> Result<(), UrnBuilderError> {
        let valid_protocols = ["stream", "amqp", "obdc", "http"];
        if valid_protocols.contains(&self.protocol.as_str()) {
            Ok(())
        } else {
            Err(UrnBuilderError::InvalidProtocol(self.protocol.clone()))
        }
    }

    fn validate_dwa(&self) -> Result<(), Vec<UrnBuilderError>> {
        let mut errors = Vec::new();

        if let Err(e) = Self::validate_required_field(&self.protocol, "protocol") {
            errors.push(e);
        } else if let Err(e) = self.validate_protocol() {
            errors.push(e);
        }

        if let Err(e) = Self::validate_required_field(&self.provider, "provider") {
            errors.push(e);
        } else if let Err(e) = self.validate_provider() {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_psa_bsa(&self) -> Result<(), Vec<UrnBuilderError>> {
        let mut errors = Vec::new();

        if let Err(e) = Self::validate_required_field(&self.rail, "rail") {
            errors.push(e);
        } else if let Err(e) = self.validate_rail() {
            errors.push(e);
        }

        if let Err(e) = Self::validate_required_field(&self.provider, "provider") {
            errors.push(e);
        } else if let Err(e) = self.validate_provider() {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_no_rail_provider(&self) -> Result<(), Vec<UrnBuilderError>> {
        let mut errors = Vec::new();

        if !["psa", "bsa", "dwa"].contains(&self.product.as_str()) {
            if !self.rail.trim().is_empty() {
                errors.push(UrnBuilderError::InvalidRail(format!(
                    "Rail should not be provided for product '{}'",
                    self.product
                )));
            }
            if !self.provider.trim().is_empty() {
                errors.push(UrnBuilderError::InvalidProvider(format!(
                    "Provider should not be provided for product '{}'",
                    self.product
                )));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_no_protocol_provider(&self) -> Result<(), Vec<UrnBuilderError>> {
        let mut errors = Vec::new();

        if self.product != "dwa" {
            if !self.protocol.trim().is_empty() {
                errors.push(UrnBuilderError::InvalidProtocol(format!(
                    "Protocol should not be provided for product '{}'",
                    self.product
                )));
            }
            if !self.provider.trim().is_empty() {
                errors.push(UrnBuilderError::InvalidProvider(format!(
                    "Provider should not be provided for product '{}'",
                    self.product
                )));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate(&self) -> Result<(), Vec<UrnBuilderError>> {
        let mut errors: Vec<_> = [
            Self::validate_required_field(&self.organization_id, "organization_id"),
            Self::validate_required_field(&self.tenant_id, "tenant_id"),
            Self::validate_required_field(&self.entity_type, "entity_type"),
            Self::validate_required_field(&self.entity_id, "entity_id"),
            Self::validate_required_field(&self.product, "product"),
            self.validate_product(),
            self.validate_region(),
            self.validate_cloud_provider(),
        ]
        .into_iter()
        .filter_map(Result::err)
        .collect();

        if ["psa", "bsa"].contains(&self.product.as_str()) {
            if let Err(mut e) = self.validate_psa_bsa() {
                errors.append(&mut e);
            }
        } else if self.product == "dwa" {
            if let Err(mut e) = self.validate_dwa() {
                errors.append(&mut e);
            }
        } else {
            if let Err(mut e) = self.validate_no_rail_provider() {
                errors.append(&mut e);
            }
            if let Err(mut e) = self.validate_no_protocol_provider() {
                errors.append(&mut e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn build(self) -> Result<String, Vec<UrnBuilderError>> {
        self.validate()?;

        Ok(GuardiaUrn {
            organization_id: self.organization_id,
            tenant_id: self.tenant_id,
            cloud_provider: self.cloud_provider,
            region: self.region,
            product: self.product,
            rail: self.rail,
            provider: self.provider,
            protocol: self.protocol,
            entity_type: self.entity_type,
            entity_id: self.entity_id,
        }
        .to_string())
    }

    pub fn from_env() -> Result<Self, UrnBuilderError> {
        dotenv().ok();

        let organization_id = env::var("ORGANIZATION_ID")
            .map_err(|_| UrnBuilderError::MissingRequiredField("ORGANIZATION_ID".into()))?;
        let tenant_id = env::var("TENANT_ID")
            .map_err(|_| UrnBuilderError::MissingRequiredField("TENANT_ID".into()))?;
        let product = env::var("PRODUCT")
            .map_err(|_| UrnBuilderError::MissingRequiredField("PRODUCT".into()))?;
        let rail = env::var("RAIL").unwrap_or_default();
        let payment_provider = env::var("PAYMENT_PROVIDER").unwrap_or_default();
        let banking_provider = env::var("BANKING_PROVIDER").unwrap_or_default();
        let protocol = env::var("PROTOCOL").unwrap_or_default();
        let data_provider = env::var("DATA_PROVIDER").unwrap_or_default();

        Ok(Self {
            organization_id,
            tenant_id,
            cloud_provider: String::new(),
            region: String::new(),
            product,
            rail,
            provider: payment_provider,
            protocol,
            entity_type: banking_provider,
            entity_id: data_provider,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_valid_urn_construction() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_product("lke")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_ok());
        let urn = urn.unwrap();
        assert_eq!(
            urn,
            "urn:guardia:org:1234567890:tenant:1234567890:[aws:us-east-1]:lke:user:1234567890"
        );
    }

    #[test]
    fn test_missing_required_organization_id() {
        let urn = UrnBuilder::new()
            .with_tenant_id("1234567890")
            .with_product("lke")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::MissingRequiredField(field) if field == "organization_id")));
    }

    #[test]
    fn test_missing_required_tenant_id() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_product("lke")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(
            |e| matches!(e, UrnBuilderError::MissingRequiredField(field) if field == "tenant_id")
        ));
    }

    #[test]
    fn test_missing_required_product() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(
            |e| matches!(e, UrnBuilderError::MissingRequiredField(field) if field == "product")
        ));
    }

    #[test]
    fn test_missing_required_entity_type() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_product("lke")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(
            |e| matches!(e, UrnBuilderError::MissingRequiredField(field) if field == "entity_type")
        ));
    }

    #[test]
    fn test_missing_required_entity_id() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_product("lke")
            .with_entity_type("user")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(
            |e| matches!(e, UrnBuilderError::MissingRequiredField(field) if field == "entity_id")
        ));
    }

    #[test]
    fn test_invalid_product() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_product("invalid_product")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProduct(product) if product == "invalid_product")));
    }

    #[test]
    fn test_invalid_cloud_provider() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("invalid_provider")
            .with_region("us-east-1")
            .with_product("lke")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidCloudProvider(provider) if provider == "invalid_provider")));
    }

    #[test]
    fn test_invalid_region() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("invalid_region")
            .with_product("lke")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(
            |e| matches!(e, UrnBuilderError::InvalidRegion(region, _) if region == "invalid_region")
        ));
    }

    #[test]
    fn test_psa_product_with_rail_and_provider() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_product("psa")
            .with_rail("p2p")
            .with_provider("guardia")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_ok());
        let urn = urn.unwrap();
        assert_eq!(urn, "urn:guardia:org:1234567890:tenant:1234567890:[aws:us-east-1]:p2p:guardia:psa:user:1234567890");
    }

    #[test]
    fn test_dwa_product_with_protocol_and_provider() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_tenant_id("1234567890")
            .with_product("dwa")
            .with_protocol("http")
            .with_provider("guardia")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_ok());
        let urn = urn.unwrap();
        assert_eq!(urn, "urn:guardia:org:1234567890:tenant:1234567890:[aws:us-east-1]:dwa:guardia:http:user:1234567890");
    }

    #[test]
    fn test_invalid_rail_for_psa() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_product("psa")
            .with_rail("invalid_rail")
            .with_provider("guardia")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, UrnBuilderError::InvalidRail(rail) if rail == "invalid_rail")));
    }

    #[test]
    fn test_invalid_protocol_for_dwa() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_product("dwa")
            .with_protocol("invalid_protocol")
            .with_provider("http")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProtocol(protocol) if protocol == "invalid_protocol")));
    }

    #[test]
    fn test_invalid_provider_with_dwa() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_product("dwa")
            .with_rail("p2p")
            .with_provider("invalid_provider")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProvider(provider) if provider == "invalid_provider")));
    }

    #[test]
    fn test_invalid_provider_with_psa() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_tenant_id("1234567890")
            .with_product("psa")
            .with_rail("p2p")
            .with_provider("invalid_provider")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProvider(provider) if provider == "invalid_provider")));
    }

    #[test]
    fn test_empty_rail_and_provider_when_not_psa() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_product("lke")
            .with_rail("pix")
            .with_provider("guardia")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidRail(rail) if rail.contains("Rail should not be provided for product 'lke'"))));
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProvider(provider) if provider.contains("Provider should not be provided for product 'lke'"))));
    }

    #[test]
    fn test_empty_rail_and_provider_when_not_dwa() {
        let urn = UrnBuilder::new()
            .with_organization_id("1234567890")
            .with_tenant_id("1234567890")
            .with_cloud_provider("aws")
            .with_region("us-east-1")
            .with_product("lke")
            .with_protocol("stream")
            .with_provider("kafka")
            .with_entity_type("user")
            .with_entity_id("1234567890")
            .build();

        assert!(urn.is_err());
        let errors = urn.unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProtocol(rail) if rail.contains("Protocol should not be provided for product 'lke'"))));
        assert!(errors.iter().any(|e| matches!(e, UrnBuilderError::InvalidProvider(provider) if provider.contains("Provider should not be provided for product 'lke'"))));
    }

    #[test]
    fn test_from_env() {        
        env::set_var("ORGANIZATION_ID", "1234567890");
        env::set_var("TENANT_ID", "0987654321");
        env::set_var("PRODUCT", "lke");
        env::set_var("RAIL", "p2p");
        env::set_var("PAYMENT_PROVIDER", "guardia");
        env::set_var("BANKING_PROVIDER", "banking");
        env::set_var("PROTOCOL", "http");
        env::set_var("DATA_PROVIDER", "data");

        
        let urn_builder = UrnBuilder::from_env();
        
        assert!(urn_builder.is_ok());
        let urn_builder = urn_builder.unwrap();

        assert_eq!(urn_builder.organization_id, "1234567890");
        assert_eq!(urn_builder.tenant_id, "0987654321");
        assert_eq!(urn_builder.product, "lke");
        assert_eq!(urn_builder.rail, "p2p");
        assert_eq!(urn_builder.provider, "guardia");
        assert_eq!(urn_builder.entity_type, "banking");
        assert_eq!(urn_builder.protocol, "http");
        assert_eq!(urn_builder.entity_id, "data");
    }
}
