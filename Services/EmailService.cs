using Azure;
using Azure.Communication.Email;

namespace MinhaApiJwt.Services
{
  public class EmailService
  {
    private readonly IConfiguration _configuration;
    private readonly EmailClient _emailClient;
    private readonly string _senderAddress;

    public EmailService(IConfiguration configuration, EmailClient emailClient)
    {
      _configuration = configuration;
      _emailClient = emailClient;
      _senderAddress = configuration["EmailSenderAddress"] ?? throw new InvalidOperationException("Email sender address not set");
    }

    public async Task sendEmailAsync(string to, string subject, string htmlContent, CancellationToken cancellationToken)
    {
      var emailContent = new EmailContent(subject)
      {
        Html = htmlContent
      };

      var recipient = new EmailAddress(to);
      var recipients = new EmailRecipients(new List<EmailAddress> { recipient });

      var emailMessage = new EmailMessage(
        senderAddress: _senderAddress,
        recipients: recipients,
        content: emailContent
      );

      EmailSendOperation emailSendOperation = await _emailClient.SendAsync(WaitUntil.Completed, emailMessage);
    }
  }
}