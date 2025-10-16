
"""Enterprise user management functionality for Keeper SDK."""

import json
import re
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlunparse

from . import enterprise_types
from .. import utils, crypto, generator
from ..proto import enterprise_pb2
from ..authentication import keeper_auth

# Constants defined here instead of importing from constants
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PBKDF2_ITERATIONS = 1_000_000


@dataclass
class CreateUserRequest:
    """Request parameters for creating an enterprise user."""
    email: str
    display_name: Optional[str] = None
    node_id: Optional[int] = None
    node_name: Optional[str] = None  # Alternative to node_id for resolution by name
    password_length: int = 20
    suppress_email_invite: bool = False


@dataclass
class CreateUserResponse:
    """Response from enterprise user creation."""
    enterprise_user_id: int
    email: str
    generated_password: str
    display_name: Optional[str] = None
    node_id: int = 0
    success: bool = True
    message: Optional[str] = None
    verification_code: Optional[str] = None


class EnterpriseUserCreationError(Exception):
    """Exception raised when enterprise user creation fails."""
    
    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code
        super().__init__(self.message)


class EnterpriseUserManager:
    """Manages enterprise user creation operations."""
    
    EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    def __init__(self, loader: enterprise_types.IEnterpriseLoader, auth_context):
        """Initialize the enterprise user manager.
        
        Args:
            loader: Enterprise data loader interface
            auth_context: Authentication context for API calls
        """
        self.loader = loader
        self.auth = auth_context
        
    def validate_email(self, email: str) -> bool:
        """Validate email format.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email is valid, False otherwise
        """
        if not email:
            return False
        
        return bool(re.match(self.EMAIL_PATTERN, email))
    
    def resolve_node_id(self, node_name_or_id: Optional[str] = None) -> int:
        """Resolve node ID from name or ID string.
        
        Args:
            node_name_or_id: Node name or ID, None for root node
            
        Returns:
            Resolved node ID
            
        Raises:
            EnterpriseUserCreationError: If node cannot be resolved
        """
        if not node_name_or_id:
            # Use root node if no specific node specified
            root_node = self.loader.enterprise_data.root_node
            if root_node:
                return root_node.node_id
            raise EnterpriseUserCreationError("Cannot determine root node")
        
        # Try to parse as integer ID first
        try:
            node_id = int(node_name_or_id)
            # Verify node exists
            enterprise_data = self.loader.enterprise_data
            if enterprise_data.nodes.get_entity(node_id):
                return node_id
            raise EnterpriseUserCreationError(f"Node with ID {node_id} not found")
        except ValueError:
            pass
        
        # Try to resolve by name
        enterprise_data = self.loader.enterprise_data
        matching_nodes = [
            node for node in enterprise_data.nodes.get_all_entities() 
            if node.name == node_name_or_id
        ]
        
        if len(matching_nodes) == 0:
            raise EnterpriseUserCreationError(f"Node '{node_name_or_id}' not found")
        elif len(matching_nodes) > 1:
            raise EnterpriseUserCreationError(
                f"Multiple nodes found with name '{node_name_or_id}'"
            )
        
        return matching_nodes[0].node_id
    
    def create_provision_request(
        self, 
        request: CreateUserRequest, 
        resolved_node_id: int
    ) -> tuple[enterprise_pb2.EnterpriseUsersProvisionRequest, str]:
        """Create a user provision request with cryptographic setup.
        
        Args:
            request: User creation request parameters
            resolved_node_id: Resolved node ID for user placement
            
        Returns:
            Tuple of (provision_request, generated_password)
            
        Raises:
            EnterpriseUserCreationError: If request creation fails
        """
        try:
            enterprise_data = self.loader.enterprise_data
            tree_key = enterprise_data.enterprise_info.tree_key
            
            # Create main request
            rq = enterprise_pb2.EnterpriseUsersProvisionRequest()
            rq.clientVersion = getattr(self.auth.keeper_endpoint, 'client_version', '')
            
            # Generate user data and password
            data = {'displayname': request.display_name or request.email}
            user_data = json.dumps(data).encode('utf-8')
            user_password = generator.KeeperPasswordGenerator(
                length=20
            ).generate()
            user_data_key = utils.generate_aes_key()
            enterprise_user_id = self.loader.get_enterprise_id()
            
            # Create user provision request
            user_rq = enterprise_pb2.EnterpriseUsersProvision()
            user_rq.enterpriseUserId = enterprise_user_id
            user_rq.username = request.email
            user_rq.nodeId = resolved_node_id
            user_rq.encryptedData = utils.base64_url_encode(
                crypto.encrypt_aes_v1(user_data, tree_key)
            )
            user_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY
            
            # Set display name and email
            # if display_name:
            #     user_rq.fullName = display_name
            # user_rq.email = email
            # user_rq.suppressEmailInvite = request.suppress_email_invite
            
            # Get enterprise EC key
            enterprise_ec_key = enterprise_data.enterprise_info.ec_public_key
            if not enterprise_ec_key:
                enterprise_ec_key = crypto.load_ec_public_key(
                    utils.base64_url_decode(
                        self.auth.auth_context.enterprise_ec_public_key
                    )
                )
            
            # Encrypt user data key
            user_rq.enterpriseUsersDataKey = crypto.encrypt_ec(
                user_data_key, enterprise_ec_key
            )
            
            # Create auth verifier and encryption params
            user_rq.authVerifier = utils.create_auth_verifier(
                user_password,
                crypto.get_random_bytes(16),
                PBKDF2_ITERATIONS
            )
            user_rq.encryptionParams = utils.create_encryption_params(
                user_password,
                crypto.get_random_bytes(16),
                PBKDF2_ITERATIONS,
                user_data_key
            )
            
            # Generate RSA keys if not forbidden
            if not getattr(self.auth.auth_context, 'forbid_rsa', False):
                rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
                rsa_private = crypto.unload_rsa_private_key(rsa_private_key)
                rsa_public = crypto.unload_rsa_public_key(rsa_public_key)
                user_rq.rsaPublicKey = rsa_public
                user_rq.rsaEncryptedPrivateKey = crypto.encrypt_aes_v1(
                    rsa_private, user_data_key
                )
            
            # Generate EC keys
            ec_private_key, ec_public_key = crypto.generate_ec_key()
            ec_private = crypto.unload_ec_private_key(ec_private_key)
            ec_public = crypto.unload_ec_public_key(ec_public_key)
            user_rq.eccPublicKey = ec_public
            user_rq.eccEncryptedPrivateKey = crypto.encrypt_aes_v2(
                ec_private, user_data_key
            )
            
            # Set device token and client key
            user_rq.encryptedDeviceToken = self.auth.auth_context.device_token
            user_rq.encryptedClientKey = crypto.encrypt_aes_v1(
                utils.generate_aes_key(), user_data_key
            )
            
            rq.users.append(user_rq)
            return rq, user_password
            
        except Exception as e:
            raise EnterpriseUserCreationError(f"Failed to create provision request: {str(e)}")
    
    def execute_provision_request(
        self, 
        provision_request: enterprise_pb2.EnterpriseUsersProvisionRequest,
        email: str
    ) -> enterprise_pb2.EnterpriseUsersProvisionResponse:
        """Execute the user provision request via API.
        
        Args:
            provision_request: The provision request to execute
            email: User email for error reporting
            
        Returns:
            Provision response from server
            
        Raises:
            EnterpriseUserCreationError: If provisioning fails
        """
        try:
            rs = self.auth.execute_auth_rest(
                'enterprise/enterprise_user_provision',
                provision_request,
                response_type=enterprise_pb2.EnterpriseUsersProvisionResponse
            )
            
            # Check for errors in response
            for user_rs in rs.results:
                if user_rs.code == "exists":
                    raise EnterpriseUserCreationError(
                        f'User "{email}" already exists',
                        code="exists"
                    )
                if user_rs.code and user_rs.code not in ['success', 'ok']:
                    doc_url = (
                        'https://docs.keeper.io/enterprise-guide/'
                        'user-and-team-provisioning/email-auto-provisioning'
                    )
                    raise EnterpriseUserCreationError(
                        f'Failed to auto-create account "{email}".\n'
                        'Creating user accounts without email verification is '
                        'only permitted on reserved domains.\n'
                        'To reserve a domain please contact Keeper support. '
                        f'Learn more about domain reservation here:\n{doc_url}',
                        code=user_rs.code
                    )
            
            return rs
            
        except Exception as e:
            if isinstance(e, EnterpriseUserCreationError):
                raise
            raise EnterpriseUserCreationError(f"API call failed: {str(e)}")
    
    def create_user(self, request: CreateUserRequest) -> CreateUserResponse:
        """Create a new enterprise user.
        
        Args:
            request: User creation request parameters
            
        Returns:
            CreateUserResponse with user details and generated password
            
        Raises:
            EnterpriseUserCreationError: If user creation fails
        """
        # Validate input
        if not self.validate_email(request.email):
            raise EnterpriseUserCreationError(f"Invalid email format: {request.email}")
        
        # Resolve node
        try:
            # Use node_id if provided, otherwise use node_name
            node_identifier = None
            if request.node_id:
                node_identifier = str(request.node_id)
            elif request.node_name:
                node_identifier = request.node_name
            
            resolved_node_id = self.resolve_node_id(node_identifier)
        except Exception as e:
            raise EnterpriseUserCreationError(f"Node resolution failed: {str(e)}")
        
        # Create provision request
        provision_request, user_password = self.create_provision_request(
            request, resolved_node_id
        )
        
        # Execute provision
        response = self.execute_provision_request(provision_request, request.email)
        
        # Reload enterprise data to get updated user info
        self.loader.load()
        
        # Extract response details
        result = response.results[0] if response.results else None
        
        return CreateUserResponse(
            enterprise_user_id=result.enterpriseUserId if result else 0,
            email=request.email,
            generated_password=user_password,
            display_name=request.display_name,
            node_id=resolved_node_id,
            success=True,
            message=result.message if result else None,
            verification_code=getattr(result, 'verificationCode', None) if result else None
        )


def create_enterprise_user(
    loader: enterprise_types.IEnterpriseLoader,
    auth_context,
    email: str,
    display_name: Optional[str] = None,
    node_id: Optional[int] = None,
    password_length: int = 20,
    suppress_email_invite: bool = False
) -> CreateUserResponse:
    """Convenience function to create an enterprise user.
    
    Args:
        loader: Enterprise data loader
        auth_context: Authentication context
        email: User email address
        display_name: Optional display name
        node_id: Optional node ID (uses root node if None)
        password_length: Length of generated password (default 20)
        suppress_email_invite: Whether to suppress email invitation
        
    Returns:
        CreateUserResponse with user details
        
    Raises:
        EnterpriseUserCreationError: If user creation fails
    """
    request = CreateUserRequest(
        email=email,
        display_name=display_name,
        node_id=node_id,
        password_length=password_length,
        suppress_email_invite=suppress_email_invite
    )
    
    manager = EnterpriseUserManager(loader, auth_context)
    return manager.create_user(request)