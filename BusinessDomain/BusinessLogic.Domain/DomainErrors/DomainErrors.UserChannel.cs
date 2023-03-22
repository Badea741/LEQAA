using ErrorOr;

namespace BusinessLogic.Domain.DomainErrors;
public static partial class DomainErrors
{
    public static partial class UserChannel
    {
        public static Error AlreadyJoinedChannel => Error.Conflict("User.JoinedChannels", "You have already joined this channel");
        public static Error NotJoined => Error.Conflict("User.NotJoined", "You did not join to this channel");


        
    }
}