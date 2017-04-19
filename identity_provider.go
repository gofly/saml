package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"

	"github.com/gofly/go-xmlsec"
)

var (
	ErrServiceProviderNotFound = errors.New("service provider not found")
	ErrRequestExpired          = errors.New("request is expired")
)

// Session represents a user session. It is returned by the
// SessionProvider implementation's GetSession method. Fields here
// are used to set fields in the SAML assertion.
type Session struct {
	ID         string
	CreateTime time.Time
	ExpireTime time.Time
	Index      string

	NameID         string
	Groups         []string
	UserName       string
	UserEmail      string
	UserCommonName string
	UserSurname    string
	UserGivenName  string
}

// IdentityProvider implements the SAML Identity Provider role (IDP).
//
// An identity provider receives SAML assertion requests and responds
// with SAML Assertions.
//
// You must provide a keypair that is used to
// sign assertions.
//
// For each service provider that is able to use this
// IDP you must add their metadata to the ServiceProviders map.
//
// You must provide an implementation of the SessionProvider which
// handles the actual authentication (i.e. prompting for a username
// and password).
type IdentityProvider struct {
	Key              string
	Certificate      string
	MetadataURL      string
	SSOURL           string
	ServiceProviders map[string]*Metadata
}

type SSOResponse struct {
	URL          string
	SAMLResponse string
	RelayState   string
}

// Metadata returns the metadata structure for this identity provider.
func (idp *IdentityProvider) Metadata() *Metadata {
	cert, _ := pem.Decode([]byte(idp.Certificate))
	if cert == nil {
		panic("invalid IDP certificate")
	}
	certStr := base64.StdEncoding.EncodeToString(cert.Bytes)

	return &Metadata{
		EntityID:      idp.MetadataURL,
		ValidUntil:    TimeNow().Add(DefaultValidDuration),
		CacheDuration: DefaultValidDuration,
		IDPSSODescriptor: &IDPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: []KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: KeyInfo{
						Certificate: certStr,
					},
				},
				{
					Use: "encryption",
					KeyInfo: KeyInfo{
						Certificate: certStr,
					},
					EncryptionMethods: []EncryptionMethod{
						{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
						{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
						{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
						{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
					},
				},
			},
			NameIDFormat: []string{
				"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
			},
			SingleSignOnService: []Endpoint{
				{
					Binding:  HTTPRedirectBinding,
					Location: idp.SSOURL,
				},
				{
					Binding:  HTTPPostBinding,
					Location: idp.SSOURL,
				},
			},
		},
	}
}

// IdpAuthnRequest is used by IdentityProvider to handle a single authentication request.
type IdpAuthnRequest struct {
	IDP                     *IdentityProvider
	HTTPRequest             *http.Request
	RelayState              string
	RequestBuffer           []byte
	Request                 AuthnRequest
	ServiceProviderMetadata *Metadata
	ACSEndpoint             *IndexedEndpoint
	Assertion               *Assertion
	AssertionBuffer         []byte
	Response                *Response
}

// NewIdpAuthnRequest returns a new IdpAuthnRequest for the given HTTP request to the authorization
// service.
func NewIdpAuthnRequest(idp *IdentityProvider, r *http.Request) (*IdpAuthnRequest, error) {
	req := &IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: r,
	}

	switch r.Method {
	case "GET":
		compressedRequest, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
		if err != nil {
			return nil, fmt.Errorf("cannot decode request: %s", err)
		}
		req.RequestBuffer, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
		if err != nil {
			return nil, fmt.Errorf("cannot decompress request: %s", err)
		}
		req.RelayState = r.URL.Query().Get("RelayState")
	case "POST":
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		var err error
		req.RequestBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLRequest"))
		if err != nil {
			return nil, err
		}
		req.RelayState = r.PostForm.Get("RelayState")
	default:
		return nil, fmt.Errorf("method not allowed")
	}
	return req, nil
}

// Validate checks that the authentication request is valid and assigns
// the AuthnRequest and Metadata properties. Returns a non-nil error if the
// request is not valid.
func (req *IdpAuthnRequest) Validate() error {
	if err := xml.Unmarshal(req.RequestBuffer, &req.Request); err != nil {
		return err
	}

	// TODO(ross): is this supposed to be the metdata URL? or the target URL?
	//   i.e. should idp.SSOURL actually be idp.Metadata().EntityID?
	if req.Request.Destination != req.IDP.SSOURL {
		return fmt.Errorf("expected destination to be %q, not %q",
			req.IDP.SSOURL, req.Request.Destination)
	}
	if req.Request.IssueInstant.Add(MaxIssueDelay).Before(TimeNow()) {
		return ErrRequestExpired
	}
	if req.Request.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2, got %q", req.Request.Version)
	}

	// find the service provider
	serviceProvider, serviceProviderFound := req.IDP.ServiceProviders[req.Request.Issuer.Value]
	if !serviceProviderFound {
		return ErrServiceProviderNotFound
	}
	req.ServiceProviderMetadata = serviceProvider

	// Check that the ACS URL matches an ACS endpoint in the SP metadata.
	acsValid := false
	for _, acsEndpoint := range serviceProvider.SPSSODescriptor.AssertionConsumerService {
		if req.Request.AssertionConsumerServiceURL == "" || req.Request.AssertionConsumerServiceURL == acsEndpoint.Location {
			req.ACSEndpoint = &acsEndpoint
			acsValid = true
			break
		}
	}
	if !acsValid {
		return fmt.Errorf("invalid ACS url specified in request: %s", req.Request.AssertionConsumerServiceURL)
	}

	return nil
}

// MakeAssertion produces a SAML assertion for the
// given request and assigns it to req.Assertion.
func (req *IdpAuthnRequest) MakeAssertion(session *Session) error {
	signatureTemplate := xmlsec.DefaultSignature([]byte(req.IDP.Certificate))
	attributes := []Attribute{}
	if session.UserName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonPrincipalName",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	if session.UserCommonName != "" {
		attributes = append(attributes, Attribute{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{{
				Type:  "xs:string",
				Value: session.UserCommonName,
			}},
		})
	}

	if len(session.Groups) != 0 {
		groupMemberAttributeValues := []AttributeValue{}
		for _, group := range session.Groups {
			groupMemberAttributeValues = append(groupMemberAttributeValues, AttributeValue{
				Type:  "xs:string",
				Value: group,
			})
		}
		attributes = append(attributes, Attribute{
			FriendlyName: "eduPersonAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       groupMemberAttributeValues,
		})
	}
	idStr := fmt.Sprintf("id-%x", randomBytes(20))
	signatureTemplate.SignedInfo.Reference.URI = fmt.Sprintf("#%s", idStr)
	req.Assertion = &Assertion{
		ID:           idStr,
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: &Issuer{
			Value: req.IDP.Metadata().EntityID,
		},
		Signature: &signatureTemplate,
		Subject: &Subject{
			NameID: &NameID{
				Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
				NameQualifier:   req.IDP.Metadata().EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           session.NameID,
			},
			SubjectConfirmation: &SubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: SubjectConfirmationData{
					Address:      req.HTTPRequest.RemoteAddr,
					InResponseTo: req.Request.ID,
					NotOnOrAfter: TimeNow().Add(MaxIssueDelay),
					Recipient:    req.ACSEndpoint.Location,
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    TimeNow(),
			NotOnOrAfter: TimeNow().Add(MaxIssueDelay),
			AudienceRestriction: &AudienceRestriction{
				Audience: &Audience{Value: req.ServiceProviderMetadata.EntityID},
			},
		},
		AuthnStatement: &AuthnStatement{
			AuthnInstant: session.CreateTime,
			SessionIndex: session.Index,
			SubjectLocality: SubjectLocality{
				Address: req.HTTPRequest.RemoteAddr,
			},
			AuthnContext: AuthnContext{
				AuthnContextClassRef: &AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		},
		AttributeStatement: &AttributeStatement{
			Attributes: attributes,
		},
	}

	return nil
}

// MarshalAssertion sets `AssertionBuffer` to a signed, encrypted
// version of `Assertion`.
func (req *IdpAuthnRequest) MarshalAssertion() error {
	buf, err := xml.Marshal(req.Assertion)
	if err != nil {
		return err
	}

	buf, err = xmlsec.Sign([]byte(req.IDP.Key),
		buf, xmlsec.SignatureOptions{
			XMLID: []xmlsec.XMLIDOption{
				xmlsec.XMLIDOption{
					ElementName:      "Assertion",
					ElementNamespace: "urn:oasis:names:tc:SAML:2.0:assertion",
					AttributeName:    "ID",
				},
			},
		})
	if err != nil {
		return err
	}

	encryptionCert := getSPEncryptionCert(req.ServiceProviderMetadata)
	if encryptionCert != nil {
		buf, err = xmlsec.Encrypt(encryptionCert, buf, xmlsec.EncryptOptions{})
		if err != nil {
			return err
		}
	}

	req.AssertionBuffer = bytes.TrimPrefix(buf, []byte("<?xml version=\"1.0\"?>"))
	return nil
}

// MakeResponse creates and assigns a new SAML response in Response. `Assertion` must
// be non-nill. If MarshalAssertion() has not been called, this function calls it for
// you.
func (req *IdpAuthnRequest) MakeResponse() error {
	if req.AssertionBuffer == nil {
		if err := req.MarshalAssertion(); err != nil {
			return err
		}
	}
	req.Response = &Response{
		Destination:  req.ACSEndpoint.Location,
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: req.Request.ID,
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: &Issuer{
			Value: req.IDP.MetadataURL,
		},
		Status: &Status{
			StatusCode: StatusCode{
				Value: StatusSuccess,
			},
		},
		EncryptedAssertion: &EncryptedAssertion{
			EncryptedData: req.AssertionBuffer,
		},
	}
	return nil
}

// GetSSOResponse get the `SSOResponse`.
// If `Response` is not already set, it calls MakeResponse to produce it.
func (req *IdpAuthnRequest) GetSSOResponse(session *Session) (*SSOResponse, error) {
	// we have a valid session and must make a SAML assertion
	if err := req.MakeAssertion(session); err != nil {
		err = fmt.Errorf("failed to make assertion: %s", err)
		return nil, err
	}

	if req.Response == nil {
		if err := req.MakeResponse(); err != nil {
			return nil, err
		}
	}
	responseBuf, err := xml.Marshal(req.Response)
	if err != nil {
		return nil, err
	}

	// the only supported binding is the HTTP-POST binding
	if req.ACSEndpoint.Binding != HTTPPostBinding {
		return nil, fmt.Errorf("%s: unsupported binding %s",
			req.ServiceProviderMetadata.EntityID,
			req.ACSEndpoint.Binding)
	}

	return &SSOResponse{
		URL:          req.ACSEndpoint.Location,
		SAMLResponse: base64.StdEncoding.EncodeToString(append([]byte(xml.Header), responseBuf...)),
		RelayState:   req.RelayState,
	}, nil
}

// getSPEncryptionCert returns the certificate which we can use to encrypt things
// to the SP in PEM format, or nil if no such certificate is found.
func getSPEncryptionCert(sp *Metadata) []byte {
	cert := ""
	for _, keyDescriptor := range sp.SPSSODescriptor.KeyDescriptor {
		if keyDescriptor.Use == "encryption" {
			cert = keyDescriptor.KeyInfo.Certificate
			break
		}
	}

	// If there are no explicitly signing certs, just return the first
	// non-empty cert we find.
	if cert == "" {
		for _, keyDescriptor := range sp.SPSSODescriptor.KeyDescriptor {
			if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
				cert = keyDescriptor.KeyInfo.Certificate
				break
			}
		}
	}

	if cert == "" {
		return nil
	}

	// cleanup whitespace and re-encode a PEM
	cert = regexp.MustCompile("\\s+").ReplaceAllString(cert, "")
	certBytes, _ := base64.StdEncoding.DecodeString(cert)
	certBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes})
	return certBytes
}
