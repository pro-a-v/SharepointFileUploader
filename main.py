import sys
import os
import re
import requests
import xml.etree.ElementTree as et
from datetime import datetime, timedelta
from xml.sax.saxutils import escape
import logging

# XML namespace URLs
ns = {
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "psf": "http://schemas.microsoft.com/Passport/SoapServices/SOAPFault",
    "d": "http://schemas.microsoft.com/ado/2007/08/dataservices",
    "S": "http://www.w3.org/2003/05/soap-envelope"
}

class SharePointSession(requests.Session):

    def __init__(self, site=None, int_site=None, folder=None, file_name=None, username=None, password=None, auth_tld=None):
        super().__init__()

        if site is not None:
            self.site = re.sub(r"^https?://", "", site)
            self.int_site = int_site
            self.folder = folder
            self.auth_tld = auth_tld or "com"
            self.expire = datetime.now()
            self.clear_filename = os.path.basename(file_name)
            self.uploadUrl = site + int_site + "/_api/web/getFolderByServerRelativeUrl('"+folder+"')/Files/add(url='" + self.clear_filename + "',overwrite=true)"
            try:
                self.file_data = open(file_name, 'rb').read()
            except Exception as e:
                print('Could not load file:',file_name)
                print(e)
                os._exit(0)

            self.filename = file_name
            # Request credentials from user
            self.username = username
            self.password = password

            if self._spauth():
                self._redigest()
                self.headers.update({
                    "Accept": "application/json; odata=verbose",
                    "Content-type": "application/json; odata=verbose"
                })

    def _spauth(self):
        """Authorise SharePoint session by generating session cookie"""
        # Load SAML request template
        #with open(os.path.join(os.path.dirname(__file__), "saml-template.xml"), "r") as file:
        #    saml = file.read()

        saml = '''
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
      xmlns:a="http://www.w3.org/2005/08/addressing"
      xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">https://login.microsoftonline.com/extSTS.srf</a:To>
    <o:Security s:mustUnderstand="1"
       xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <o:UsernameToken>
        <o:Username>{username}</o:Username>
        <o:Password>{password}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>{site}</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
      <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>
        '''


        saml = saml.format(username=escape(self.username), password=escape(self.password), site=self.site)

        # Request security token from Microsoft Online
        print("Requesting security token...\r")
        auth_domain = "login.microsoftonline." + self.auth_tld
        try:
            response = requests.post("https://{}/extSTS.srf".format(auth_domain), data=saml)
        except requests.exceptions.ConnectionError:
            print("Could not connect to", auth_domain)
            return
        # Parse and extract token from returned XML
        try:
            root = et.fromstring(response.text)
        except et.ParseError:
            print("Token request failed. The server did not send a valid response")
            return

        # Extract token from returned XML
        token = root.find(".//wsse:BinarySecurityToken", ns)
        # Check for errors and print error messages
        if token is None or root.find(".//S:Fault", ns) is not None:
            print("{}: {}".format(root.find(".//S:Text", ns).text, root.find(".//psf:text", ns).text).strip().strip("."))
            return

        # Request access token from sharepoint site
        print("Requesting access cookie... \r")
        response = requests.post("https://" + self.site + "/_forms/default.aspx?wa=wsignin1.0", data=token.text, headers={"Host": self.site})

        # Create access cookie from returned headers
        cookie = self._buildcookie(response.cookies)
        # Verify access by requesting page
        response = requests.get("https://" + self.site + "/_api/web", headers={"Cookie": cookie})

        if response.status_code == requests.codes.ok:
            self.headers.update({"Cookie": cookie})
            self.cookie = cookie
            print("Authentication successful   ")
            return True
        else:
            print("Authentication failed       ")

    def _redigest(self):
        """Check and refresh site's request form digest"""
        if self.expire <= datetime.now():
            # Request site context info from SharePoint site
            response = requests.post("https://" + self.site + "/_api/contextinfo", data="", headers={"Cookie": self.cookie})
            # Parse digest text and timeout from XML
            try:
                root = et.fromstring(response.text)
                self.digest = root.find(".//d:FormDigestValue", ns).text
                timeout = int(root.find(".//d:FormDigestTimeoutSeconds", ns).text)
                self.headers.update({"Cookie": self._buildcookie(response.cookies)})
            except:
                print("Digest request failed")
                return
            # Calculate digest expiry time
            self.expire = datetime.now() + timedelta(seconds=timeout)

        return self.digest

    '''
    def post(self, url, *args, **kwargs):
        """Make POST request and include authorisation headers"""
        if "headers" not in kwargs.keys():
            kwargs["headers"] = {}
        kwargs["headers"]["Authorization"] = "Bearer " + self._redigest()
        return super().post(url, *args, **kwargs)
        '''

    def post(self, *args, **kwargs):
        """Make POST request and include authorisation headers"""
        if "headers" not in kwargs.keys():
            kwargs["headers"] = {}
        kwargs["headers"]["Authorization"] = "Bearer " + self._redigest()
        return super().post(self.uploadUrl , data=self.file_data, *args, **kwargs)

    def _buildcookie(self, cookies):
        """Create session cookie from response cookie dictionary"""
        return "rtFa=" + cookies["rtFa"] + "; FedAuth=" + cookies["FedAuth"]

if __name__ == '__main__':
    if len(sys.argv)<6:
        print('Usage: file shrepoint_url site folder file_name username password')
        print('example: file https://gmsworldwide.sharepoint.com  /teams/td-nod-srv /teams/td-nod-srv/External/Devino-Logs /home/a.prochakovsky/PycharmProjects/Microsoft/SharePoint/bug.png username password')
        os._exit(0)

    '''
    # Logging Requests
    import http.client as http_client

    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
    '''

    s = SharePointSession(site=sys.argv[1], int_site=sys.argv[2], folder=sys.argv[3],file_name=sys.argv[4], username=sys.argv[5], password=sys.argv[6])
    ret = s.post()
    print(ret)




