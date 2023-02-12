using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace Authentication.Entry.Options;
public class CorsPolicyBuilderSetup : IConfigureOptions<CorsOptions>
{
    public void Configure(CorsOptions options)
    {
        options.AddPolicy("MyPolicy", builder =>
                {
                    builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
    }
}
