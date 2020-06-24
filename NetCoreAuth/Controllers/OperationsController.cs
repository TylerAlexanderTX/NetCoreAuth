using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace NetCoreAuth.Controllers
{
    public class OperationsController : Controller
    {
        private readonly IAuthorizationService _authorizationService;

        public OperationsController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }

        public async Task<IActionResult> Open()
        {
            var itemBox = new ItemBox(); //get the resource
            
            //Pass to a function based on the resource
            await _authorizationService.AuthorizeAsync(User, itemBox, DemoAuthOpertations.Open);
            return View();
        }
    }

    public class DemoAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, ItemBox>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OperationAuthorizationRequirement requirement, ItemBox itemBox)
        {
            //operations for the resource
            if(requirement.Name == DemoOperations.Look)
            {
                if(context.User.Identity.IsAuthenticated)
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }

    public static class DemoAuthOpertations
    {
        public static OperationAuthorizationRequirement Open = new OperationAuthorizationRequirement
        {
            Name = DemoOperations.Open
        };
    }


    public static class DemoOperations
    {
        public static string Open = "Open";

        public static string TakeItem = "TakeItem";

        public static string Look = "Look";

    }

    public class ItemBox
    {
        public string Name { get; set; }
    }

}