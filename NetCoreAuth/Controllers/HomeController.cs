using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace NetCoreAuth.Controllers
{
    public class HomeController : Controller
    {
        // GET: /<controller>/
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        [Authorize (Policy = "Claim.DoB")]
        public IActionResult SecretPolicy()
        {
            return View("Secret");
        }

        public IActionResult Authenticate()
        {
            var demoClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@email.com"),
            };

            var driversLicenseClaim = new List<Claim>
            { 
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.SerialNumber, "987654"),
                new Claim(ClaimTypes.StreetAddress, "123 Test St")
            };

            var demoIdentity = new ClaimsIdentity(demoClaims, "Demo Identity");
            var licenseIdentity = new ClaimsIdentity(driversLicenseClaim, "DL Identity");

            //principal is a collection of identities and claims
            var userPrincipal = new ClaimsPrincipal(new[] { demoIdentity, licenseIdentity });

            HttpContext.SignInAsync(userPrincipal);

            return RedirectToAction("Index");
        }
    }
}
