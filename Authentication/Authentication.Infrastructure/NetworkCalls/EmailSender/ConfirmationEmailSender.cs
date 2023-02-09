using System.Web;
using Authentication.Application.Interfaces;
using Authentication.Infrastructure.Models;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Authentication.Infrastructure.NetworkCalls.EmailSender;
public class ConfirmationEmailSender : IEmailSender
{
    private readonly Smtp Smtp;
    private readonly IConfiguration _configuration;

    public ConfirmationEmailSender(IOptions<Smtp> smtp, IConfiguration configuration)
    {
        Smtp = smtp.Value;
        _configuration = configuration;
    }
    public async Task SendAsync(string toEmail, string confirmationLink, string token = null!)
    {
        var encodedToken = HttpUtility.UrlEncode(token);
        var encodedEmail = HttpUtility.UrlEncode(toEmail);
        var messageBody =
            _configuration.GetSection("Uri").Value +
            confirmationLink + '?' + "email=" + encodedEmail +
             '&' + "token=" + encodedToken;

        var mailMessage = new MimeMessage();
        mailMessage.From.Add(new MailboxAddress("leqaa.technical", Smtp.Email));
        mailMessage.To.Add(new MailboxAddress("", toEmail));
        mailMessage.Subject = "Email confirmation link";
        mailMessage.Body = new TextPart("plain")
        {
            Text = messageBody
        };
        using (var smtpClient = new SmtpClient())
        {
            await smtpClient.ConnectAsync(Smtp.Host, Smtp.Port, useSsl: true);
            await smtpClient.AuthenticateAsync(Smtp.Email, Smtp.Password);
            await smtpClient.SendAsync(mailMessage);
            await smtpClient.DisconnectAsync(quit: true);
        }
    }
}