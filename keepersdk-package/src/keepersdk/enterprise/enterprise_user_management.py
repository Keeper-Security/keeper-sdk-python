
"""Enterprise user management functionality for Keeper SDK."""

import json
import re
from typing import Optional
from dataclasses import dataclass

from keepersdk.authentication import keeper_auth

from . import enterprise_types
from .. import utils, crypto, generator
from ..proto import enterprise_pb2

# Constants
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PBKDF2_ITERATIONS = 1_000_000
DEFAULT_PASSWORD_LENGTH = 20
SALT_LENGTH = 16
AUTH_VERIFIER_SALT_LENGTH = 16

# Error codes
ERROR_CODE_EXISTS = "exists"
ERROR_CODE_SUCCESS = "success"
ERROR_CODE_OK = "ok"

# Documentation URLs
DOMAIN_RESERVATION_DOC_URL = (
    'https://docs.keeper.io/enterprise-guide/'
    'user-and-team-provisioning/email-auto-provisioning'
)

# Error messages
ERROR_MSG_INVALID_EMAIL = "Invalid email format: {}"
ERROR_MSG_NODE_RESOLUTION_FAILED = "Node resolution failed: {}"
ERROR_MSG_CANNOT_DETERMINE_ROOT_NODE = "Cannot determine root node"
ERROR_MSG_NODE_NOT_FOUND_BY_ID = "Node with ID {} not found"
ERROR_MSG_NODE_NOT_FOUND_BY_NAME = "Node '{}' not found"
ERROR_MSG_MULTIPLE_NODES_FOUND = "Multiple nodes found with name '{}'"
ERROR_MSG_PROVISION_REQUEST_FAILED = "Failed to create provision request: {}"
ERROR_MSG_API_CALL_FAILED = "API call failed: {}"
ERROR_MSG_USER_EXISTS = 'User "{}" already exists'
ERROR_MSG_AUTO_CREATE_FAILED = (
    'Failed to auto-create account "{}".\n'
    'Creating user accounts without email verification is '
    'only permitted on reserved domains.\n'
    'To reserve a domain please contact Keeper support. '
    'Learn more about domain reservation here:\n{}'
)


@dataclass
class CreateUserRequest:
    """Request parameters for creating an enterprise user."""
    email: str
    display_name: Optional[str] = None
    node_id: Optional[int] = None
    node_name: Optional[str] = None
    password_length: int = DEFAULT_PASSWORD_LENGTH
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
    
    def __init__(self, loader: enterprise_types.IEnterpriseLoader, auth_context: keeper_auth.KeeperAuth):
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
        
        return bool(re.match(EMAIL_PATTERN, email))
    
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
            return self._get_root_node_id()
        
        if self._is_numeric_id(node_name_or_id):
            return self._resolve_node_by_id(int(node_name_or_id))
        
        return self._resolve_node_by_name(node_name_or_id)

    def _get_root_node_id(self) -> int:
        """Get the root node ID."""
        root_node = self.loader.enterprise_data.root_node
        if root_node:
            return root_node.node_id
        raise EnterpriseUserCreationError(ERROR_MSG_CANNOT_DETERMINE_ROOT_NODE)

    def _is_numeric_id(self, node_identifier: str) -> bool:
        """Check if the node identifier is numeric."""
        try:
            int(node_identifier)
            return True
        except ValueError:
            return False

    def _resolve_node_by_id(self, node_id: int) -> int:
        """Resolve node by numeric ID."""
        enterprise_data = self.loader.enterprise_data
        if enterprise_data.nodes.get_entity(node_id):
            return node_id
        raise EnterpriseUserCreationError(ERROR_MSG_NODE_NOT_FOUND_BY_ID.format(node_id))

    def _resolve_node_by_name(self, node_name: str) -> int:
        """Resolve node by name."""
        enterprise_data = self.loader.enterprise_data
        matching_nodes = [
            node for node in enterprise_data.nodes.get_all_entities() 
            if node.name == node_name
        ]
        
        if len(matching_nodes) == 0:
            raise EnterpriseUserCreationError(ERROR_MSG_NODE_NOT_FOUND_BY_NAME.format(node_name))
        elif len(matching_nodes) > 1:
            raise EnterpriseUserCreationError(ERROR_MSG_MULTIPLE_NODES_FOUND.format(node_name))
        
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
            
            rq = enterprise_pb2.EnterpriseUsersProvisionRequest()
            rq.clientVersion = self.auth.keeper_endpoint.client_version
            
            # Generate user data and password
            user_data, user_password, user_data_key = self._generate_user_credentials(request)
            enterprise_user_id = self.loader.get_enterprise_id()
            
            # Create user provision request
            user_rq = self._create_user_provision_request(
                request, resolved_node_id, enterprise_user_id, 
                user_data, user_data_key, tree_key, user_password
            )
            
            rq.users.append(user_rq)
            return rq, user_password
            
        except Exception as e:
            raise EnterpriseUserCreationError(ERROR_MSG_PROVISION_REQUEST_FAILED.format(str(e)))

    def _generate_user_credentials(self, request: CreateUserRequest) -> tuple[bytes, str, bytes]:
        """Generate user data, password, and data key."""
        data = {'displayname': request.display_name or request.email}
        user_data = json.dumps(data).encode('utf-8')
        user_password = generator.KeeperPasswordGenerator(
            length=request.password_length
        ).generate()
        user_data_key = utils.generate_aes_key()
        return user_data, user_password, user_data_key

    def _create_user_provision_request(
        self, 
        request: CreateUserRequest, 
        resolved_node_id: int,
        enterprise_user_id: int,
        user_data: bytes, 
        user_data_key: bytes, 
        tree_key: bytes,
        user_password: str
    ) -> enterprise_pb2.EnterpriseUsersProvision:
        """Create the user provision request object."""
        user_rq = enterprise_pb2.EnterpriseUsersProvision()
        user_rq.enterpriseUserId = enterprise_user_id
        user_rq.username = request.email
        user_rq.nodeId = resolved_node_id
        user_rq.encryptedData = utils.base64_url_encode(
            crypto.encrypt_aes_v1(user_data, tree_key)
        )
        user_rq.keyType = enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY
        
        # Set up enterprise data key
        enterprise_ec_key = self._get_enterprise_ec_key()
        user_rq.enterpriseUsersDataKey = crypto.encrypt_ec(
            user_data_key, enterprise_ec_key
        )
        
        # Set up authentication and encryption
        self._setup_user_authentication(user_rq, user_password, user_data_key)
        
        # Set up cryptographic keys
        self._setup_cryptographic_keys(user_rq, user_data_key)
        
        # Set up device token and client key
        user_rq.encryptedDeviceToken = self.auth.auth_context.device_token
        user_rq.encryptedClientKey = crypto.encrypt_aes_v1(
            utils.generate_aes_key(), user_data_key
        )
        
        return user_rq

    def _get_enterprise_ec_key(self):
        """Get the enterprise EC public key."""
        enterprise_data = self.loader.enterprise_data
        enterprise_ec_key = enterprise_data.enterprise_info.ec_public_key
        if not enterprise_ec_key:
            enterprise_ec_key = crypto.load_ec_public_key(
                utils.base64_url_decode(
                    self.auth.auth_context.enterprise_ec_public_key
                )
            )
        return enterprise_ec_key

    def _setup_user_authentication(
        self, 
        user_rq: enterprise_pb2.EnterpriseUsersProvision, 
        user_password: str, 
        user_data_key: bytes
    ) -> None:
        """Set up user authentication verifier and encryption parameters."""
        user_rq.authVerifier = utils.create_auth_verifier(
            user_password,
            crypto.get_random_bytes(AUTH_VERIFIER_SALT_LENGTH),
            PBKDF2_ITERATIONS
        )
        user_rq.encryptionParams = utils.create_encryption_params(
            user_password,
            crypto.get_random_bytes(SALT_LENGTH),
            PBKDF2_ITERATIONS,
            user_data_key
        )

    def _setup_cryptographic_keys(
        self, 
        user_rq: enterprise_pb2.EnterpriseUsersProvision, 
        user_data_key: bytes
    ) -> None:
        """Set up RSA and EC cryptographic keys for the user."""
        # Set up RSA keys if not forbidden
        if not self.auth.auth_context.forbid_rsa:
            self._setup_rsa_keys(user_rq, user_data_key)
        
        # Set up EC keys
        self._setup_ec_keys(user_rq, user_data_key)

    def _setup_rsa_keys(
        self, 
        user_rq: enterprise_pb2.EnterpriseUsersProvision, 
        user_data_key: bytes
    ) -> None:
        """Set up RSA keys for the user."""
        rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
        rsa_private = crypto.unload_rsa_private_key(rsa_private_key)
        rsa_public = crypto.unload_rsa_public_key(rsa_public_key)
        user_rq.rsaPublicKey = rsa_public
        user_rq.rsaEncryptedPrivateKey = crypto.encrypt_aes_v1(
            rsa_private, user_data_key
        )

    def _setup_ec_keys(
        self, 
        user_rq: enterprise_pb2.EnterpriseUsersProvision, 
        user_data_key: bytes
    ) -> None:
        """Set up EC keys for the user."""
        ec_private_key, ec_public_key = crypto.generate_ec_key()
        ec_private = crypto.unload_ec_private_key(ec_private_key)
        ec_public = crypto.unload_ec_public_key(ec_public_key)
        user_rq.eccPublicKey = ec_public
        user_rq.eccEncryptedPrivateKey = crypto.encrypt_aes_v2(
            ec_private, user_data_key
        )
    
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
            
            self._validate_provision_response(rs, email)
            return rs
            
        except Exception as e:
            if isinstance(e, EnterpriseUserCreationError):
                raise
            raise EnterpriseUserCreationError(ERROR_MSG_API_CALL_FAILED.format(str(e)))

    def _validate_provision_response(
        self, 
        response: enterprise_pb2.EnterpriseUsersProvisionResponse, 
        email: str
    ) -> None:
        """Validate the provision response and raise appropriate errors."""
        for user_rs in response.results:
            if user_rs.code == ERROR_CODE_EXISTS:
                raise EnterpriseUserCreationError(
                    ERROR_MSG_USER_EXISTS.format(email),
                    code=ERROR_CODE_EXISTS
                )
            if user_rs.code and user_rs.code not in [ERROR_CODE_SUCCESS, ERROR_CODE_OK]:
                raise EnterpriseUserCreationError(
                    ERROR_MSG_AUTO_CREATE_FAILED.format(email, DOMAIN_RESERVATION_DOC_URL),
                    code=user_rs.code
                )
    
    def create_user(self, request: CreateUserRequest) -> CreateUserResponse:
        """Create a new enterprise user.
        
        Args:
            request: User creation request parameters
            
        Returns:
            CreateUserResponse with user details and generated password
            
        Raises:
            EnterpriseUserCreationError: If user creation fails
        """
        self._validate_user_request(request)
        
        resolved_node_id = self._resolve_user_node(request)
        
        provision_request, user_password = self.create_provision_request(
            request, resolved_node_id
        )
        
        response = self.execute_provision_request(provision_request, request.email)
        
        # Reload enterprise data to get updated user info
        self.loader.load()
        
        return self._build_user_response(request, response, user_password, resolved_node_id)

    def _validate_user_request(self, request: CreateUserRequest) -> None:
        """Validate the user creation request."""
        if not self.validate_email(request.email):
            raise EnterpriseUserCreationError(ERROR_MSG_INVALID_EMAIL.format(request.email))

    def _resolve_user_node(self, request: CreateUserRequest) -> int:
        """Resolve the node for the user."""
        try:
            # Use node_id if provided, otherwise use node_name
            node_identifier = None
            if request.node_id:
                node_identifier = str(request.node_id)
            elif request.node_name:
                node_identifier = request.node_name
            
            return self.resolve_node_id(node_identifier)
        except Exception as e:
            raise EnterpriseUserCreationError(ERROR_MSG_NODE_RESOLUTION_FAILED.format(str(e)))

    def _build_user_response(
        self, 
        request: CreateUserRequest, 
        response: enterprise_pb2.EnterpriseUsersProvisionResponse,
        user_password: str,
        resolved_node_id: int
    ) -> CreateUserResponse:
        """Build the user creation response."""
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
    auth_context: keeper_auth.KeeperAuth,
    email: str,
    display_name: Optional[str] = None,
    node_id: Optional[int] = None,
    password_length: int = DEFAULT_PASSWORD_LENGTH,
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