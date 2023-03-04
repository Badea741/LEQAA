using BusinessLogic.Application.CommandInterfaces;
using BusinessLogic.Application.Commands.Channels.UpdateChannel;
using BusinessLogic.Application.Commands.Hubs.DeployHub;
using BusinessLogic.Application.Interfaces;
using BusinessLogic.Application.Models.Channels;
using BusinessLogic.Application.Models.Hubs;
using BusinessLogic.Domain;
using BusinessLogic.Domain.DomainErrors;
using ErrorOr;
using FluentValidation;
using Mapster;
using MediatR;

namespace BusinessLogic.Application.Commands.Hubs.UpdateHub;
public class AddHubCommandHandler : IHandler<UpdateHubCommand, ErrorOr<HubUpdateModel>>
{
    private readonly IHubRepository _hubRepository;
    private readonly IUserRepository _userRepository;
    private readonly IValidator<UpdateHubCommand> _validator;




    public AddHubCommandHandler(
        IHubRepository HubRepository,
        IHubRepository hubRepository,
        IUserRepository userRepository,
           IValidator<UpdateHubCommand> validator)
    {
        _hubRepository = hubRepository;
        _userRepository = userRepository;
        _validator = validator;

    }

    public async Task<ErrorOr<HubUpdateModel>> Handle(UpdateHubCommand request, CancellationToken cancellationToken)
    {
        var hub = await _hubRepository.GetByIdAsync(request.hubId);

        if (request.Name != null)
            hub.Name = request.Name;
        if (request.Description != null)
            hub.Description = request.Description;
        await _hubRepository.UpdateAsync(hub);
        if (await _hubRepository.SaveAsync(cancellationToken) == 0)
        {
            return DomainErrors.Hub.InvalidHub;
        }

        return hub.Adapt<HubUpdateModel>();
    }
}
