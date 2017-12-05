using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(HashEncryption.Startup))]
namespace HashEncryption
{
    public partial class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureAuth(app);
        }
    }
}
