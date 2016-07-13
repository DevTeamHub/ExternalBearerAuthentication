using System.Security.Claims;
using System.Threading.Tasks;
using DevTeam.BearerAuthentication;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth;

namespace DevTeam.ExternalBearerAuthentication
{
    public class ExternalCredentialsValidator<TUser, TService> : OAuthBaseValidator<OAuthGrantCustomExtensionContext, TUser, TService>
        where TUser: class, IUser
        where TService: ExtendedUserManager<TUser>
    {
        public string ExternalId { get; private set; }
        public string ExternalName { get; private set; }
        public string Token { get; private set; }
        public string Provider { get; private set; }

        public ExternalCredentialsValidator(OAuthGrantCustomExtensionContext context)
            : base(context)
        {
            ExternalId = context.Parameters.Get("externalId");
            ExternalName = context.Parameters.Get("externalName");
            Token = context.Parameters.Get("token");
            Provider = context.GrantType;
        }

        public override async Task<TUser> GetUser()
        {
            var user = Service.GetExternalUser(ExternalId, ExternalName, Provider);
            return await Task.FromResult(user);
        }

        public override void AddClaims(ClaimsIdentity identity)
        {
            identity.AddClaim(new Claim(ClaimTypes.UserData, ExternalId));
            identity.AddClaim(new Claim(ClaimTypes.Name, ExternalName));
            identity.AddClaim(new Claim(ClaimTypes.Sid, Token));
            base.AddClaims(identity);
        }
    }
}
