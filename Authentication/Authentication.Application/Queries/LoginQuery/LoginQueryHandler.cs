using Authentication.Application.CommandInterfaces;
using Authentication.Application.Interfaces;
using Authentication.Application.Models;
using Authentication.Domain.Entities.ApplicationUser;
using Microsoft.AspNetCore.Identity;

namespace Authentication.Application.Queries.LoginQuery;
public class LoginQueryHandler : IHandler<LoginQuery>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenGenerator _tokenGenerator;

    public LoginQueryHandler(UserManager<ApplicationUser> userManager, ITokenGenerator tokenGenerator)
    {
        _userManager = userManager;
        _tokenGenerator = tokenGenerator;
    }

    public async Task<AuthenticationResults> Handle(LoginQuery request, CancellationToken cancellationToken)
    {
        var authenticationResults = new AuthenticationResults();
        var user = await _userManager.FindByNameAsync(request.UserName);
        if (user is null)
        {
            authenticationResults.AddErrorMessages("username doesn't exist, Please register");
            return authenticationResults;
        }
        if (!await _userManager.CheckPasswordAsync(user, request.Password))
        {
            authenticationResults.AddErrorMessages("Incorrect password");
            return authenticationResults;
        }
        var token = _tokenGenerator.Generate(user);
        authenticationResults.SetToken(token);
        authenticationResults.IsSuccess = true;
        return authenticationResults;
    }
}
