using ErrorOr;

namespace BusinessLogic.Domain.DomainErrors;
public static partial class DomainErrors
{
    public static class Channel
    {
        public static Error InvalidChannel => Error.Failure("Channel.InvalidChannel", "Invalid Channel, couldn't complete your request");
    }



    public static class Room
    {
        public static Error InvalidRoom => Error.Failure("Room.InvalidChannel", "Invalid Room, couldn't complete your request");
    }
}