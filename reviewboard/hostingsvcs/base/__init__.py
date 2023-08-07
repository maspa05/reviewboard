"""Base support for writing hosting services.

.. autosummary::
   :nosignatures:

   ~reviewboard.hostingsvcs.base.client.HostingServiceClient
   ~reviewboard.hostingsvcs.base.hosting_service.HostingService
   ~reviewboard.hostingsvcs.base.http.HostingServiceHTTPRequest
   ~reviewboard.hostingsvcs.base.http.HostingServiceHTTPResponse
   ~reviewboard.hostingsvcs.base.registry.hosting_service_registry
   ~reviewboard.hostingsvcs.base.repository.RemoteRepository

Version Added:
    6.0
"""

from reviewboard.hostingsvcs.base.client import HostingServiceClient
from reviewboard.hostingsvcs.base.hosting_service import HostingService
from reviewboard.hostingsvcs.base.http import (HostingServiceHTTPRequest,
                                               HostingServiceHTTPResponse)
from reviewboard.hostingsvcs.base.registry import hosting_service_registry
from reviewboard.hostingsvcs.base.repository import RemoteRepository


__all__ = [
    'HostingService',
    'HostingServiceClient',
    'HostingServiceHTTPRequest',
    'HostingServiceHTTPResponse',
    'hosting_service_registry',
    'RemoteRepository',
]
