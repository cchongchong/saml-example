using Owin;
using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace SamlIssuer
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Run(context =>
            {
                var replyToUrl = "https://localhost:44356/";
                var realmUrl = "https://localhost:44356/";
                var signingCertificate = new X509Certificate2(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "local-hosting.pfx"), "test");//or use GetLocalCertificate() to get it from local machine
                X509Certificate2 encryptionCertificate = null;//assign it to protect the token body

                var securityTokenHandlerCollectionManager = SecurityTokenHandlerCollectionManager.CreateEmptySecurityTokenHandlerCollectionManager();
                securityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.Default] = CreateSupportedSecurityTokenHandler();

                var claimsIdentity = new ClaimsIdentity("local", ClaimTypes.NameIdentifier, ClaimTypes.Role);
                claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "admin.user"));
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, "admin.role"));
                //add more claims

                // X509Certificate2 -> X509SigningCredentials -> X509SigningToken -> RsaSecurityToken
                var descriptor = new SecurityTokenDescriptor
                {
                    AppliesToAddress = realmUrl,
                    Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddSeconds(60)),
                    ReplyToAddress = replyToUrl,
                    SigningCredentials = new X509SigningCredentials(signingCertificate),
                    Subject = claimsIdentity,
                    TokenIssuerName = context.Request.Uri.ToString(),
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
                };
                if (encryptionCertificate != null)
                {
                    descriptor.EncryptingCredentials = new EncryptedKeyEncryptingCredentials(encryptionCertificate);
                }

                var token = securityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.Default].CreateToken(descriptor);

                var signInResponseMessage = new SignInResponseMessage(new Uri(replyToUrl),
                    response: new RequestSecurityTokenResponse
                    {
                        ReplyTo = replyToUrl,
                        RequestedSecurityToken = new RequestedSecurityToken(token)
                    },
                    federationSerializer: new WSFederationSerializer(
                        new WSTrustFeb2005RequestSerializer(),
                        new WSTrustFeb2005ResponseSerializer()),
                    context: new WSTrustSerializationContext(securityTokenHandlerCollectionManager));
                context.Response.ContentType = "text/html";
                return context.Response.WriteAsync(signInResponseMessage.WriteFormPost());
            });
        }

        private SecurityTokenHandlerCollection CreateSupportedSecurityTokenHandler()
        {
            return new SecurityTokenHandlerCollection(new SecurityTokenHandler[]
            {
                new SamlSecurityTokenHandler(),
                new EncryptedSecurityTokenHandler(),
                new Saml2SecurityTokenHandler()
            });
        }

        public X509Certificate2 GetLocalCertificate(string thumbprint)
        {
            X509Certificate2 certificate = null;

            if (!string.IsNullOrEmpty(thumbprint))
            {
                foreach (var storeName in Enum.GetValues(typeof(StoreName))
                    .Cast<StoreName>()
                    .Where(x => x == StoreName.My || x == StoreName.Root || x == StoreName.TrustedPeople || x == StoreName.TrustedPublisher))
                {
                    var store = new X509Store(storeName, StoreLocation.LocalMachine);
                    try
                    {
                        store.Open(OpenFlags.ReadOnly);
                        certificate =
                            store.Certificates.Cast<X509Certificate2>().Where(x => x.NotAfter >= DateTime.Today)
                                .FirstOrDefault(
                                    currCert =>
                                    {
                                        if (string.Equals(thumbprint, currCert.Thumbprint, StringComparison.CurrentCultureIgnoreCase))
                                        {
                                            return true;
                                        }

                                        return false;
                                    });
                    }
                    finally
                    {
                        store.Close();
                    }

                    if (certificate != null)
                    {
                        break;
                    }
                }
            }

            return certificate;
        }
    }
}