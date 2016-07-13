using System.Threading.Tasks;
using DevTeam.BearerAuthentication;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.OAuth;

namespace DevTeam.ExternalBearerAuthentication
{
    public class ExternalOAuthProvider<TUser>: ApplicationOAuthProvider<TUser, ExtendedUserManager<TUser>>
        where TUser: class, IUser
    {
        public ExternalOAuthProvider(string publicClientId)
            : base(publicClientId)
        { }

        public override async Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        {
            var grantContext = new ExternalCredentialsValidator<TUser, ExtendedUserManager<TUser>>(context);
            await grantContext.SignIn();
        }
    }
}
