using Microsoft.AspNet.Identity;
using DevTeam.BearerAuthenticationCore;

namespace DevTeam.ExternalBearerAuthentication
{
    public class ExtendedUserManager<TUser>: UserManager<TUser>
        where TUser: class, IUser
    {
        protected readonly IExternalUserStore<TUser> Service; 

        public ExtendedUserManager(IExternalUserStore<TUser> store)
            : base(store)
        {
            Service = store;
        }

        public TUser GetExternalUser(string externalId, string externalName, string provider)
        {
            return Service.GetExternalUser(externalId, externalName, provider);
        }
    }
}
