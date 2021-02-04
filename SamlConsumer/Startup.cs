using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.WsFederation;
using Newtonsoft.Json;
using Owin;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace SamlConsumer
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var issuer = "https://localhost:44365/";
            var signingCertificate = new X509Certificate2(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "local-hosting.cer"));
            var decryptionCertificate = new X509Certificate2(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "local-hosting.pfx"), "test", X509KeyStorageFlags.Exportable);
            var replyToUrl = "https://localhost:44356/";
            var realmUrl = "https://localhost:44356/";

            var wsFederationAuthenticationOptions = new WsFederationAuthenticationOptions
            {
                Wtrealm = realmUrl,
                Wreply = replyToUrl,
                SignInAsAuthenticationType = "ws-fed"
            };
            wsFederationAuthenticationOptions.Configuration = new WsFederationConfiguration
            {
                Issuer = issuer
            };
            wsFederationAuthenticationOptions.Configuration.SigningKeys.Add(new X509SecurityKey(signingCertificate));
            wsFederationAuthenticationOptions.TokenValidationParameters.ClientDecryptionTokens = new System.Collections.ObjectModel.ReadOnlyCollection<SecurityToken>(new List<SecurityToken>
            {
                new X509SecurityToken(decryptionCertificate)
            });
            app.UseWsFederationAuthentication(wsFederationAuthenticationOptions);

            app.Run(context =>
            {
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(JsonConvert.SerializeObject(new SerializablePrincipal(context.Authentication.User)));
            });
        }
    }

    public class SerializablePrincipal
    {
        public SerializablePrincipal() { }

        public SerializablePrincipal(ClaimsPrincipal claimsPrincipal)
        {
            AuthenticationType = claimsPrincipal.Identity.AuthenticationType;
            NameClaimType = (claimsPrincipal.Identity as ClaimsIdentity)?.NameClaimType;
            RoleClaimType = (claimsPrincipal.Identity as ClaimsIdentity)?.RoleClaimType;
            Claims = claimsPrincipal.Claims.Select(x => new SerializableClaim(x)).ToList();
        }

        public string AuthenticationType { get; set; }
        public string NameClaimType { get; set; }
        public string RoleClaimType { get; set; }
        public IList<SerializableClaim> Claims { get; set; }

        public ClaimsPrincipal ToClaimsPrincipal()
        {
            var identity = new ClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType);
            identity.AddClaims(Claims.Select(x => x.ToClaim()));
            return new ClaimsPrincipal(identity);
        }

        public class SerializableClaim
        {
            public SerializableClaim() { }

            public SerializableClaim(Claim claim)
            {
                OriginalIssuer = claim.OriginalIssuer;
                Issuer = claim.Issuer;
                ValueType = claim.ValueType;
                Type = claim.Type;
                Value = claim.Value;
            }

            public string OriginalIssuer { get; set; }
            public string Issuer { get; set; }
            public string ValueType { get; set; }
            public string Type { get; set; }
            public string Value { get; set; }

            public Claim ToClaim()
            {
                return new Claim(type: Type,
                    value: Value,
                    valueType: ValueType,
                    issuer: Issuer,
                    originalIssuer: OriginalIssuer);
            }
        }
    }
}