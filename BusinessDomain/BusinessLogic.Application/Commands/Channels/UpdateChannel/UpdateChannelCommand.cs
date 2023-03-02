using BusinessLogic.Application.CommandInterfaces;
using BusinessLogic.Domain;
using ErrorOr;
using MediatR;

namespace BusinessLogic.Application.Commands.Channels.UpdateChannel;
public record UpdatePostCommand(
    string Name,
    string? Description,
    Guid HubId,
    string Username
) : ICommand<ErrorOr<Channel>>;