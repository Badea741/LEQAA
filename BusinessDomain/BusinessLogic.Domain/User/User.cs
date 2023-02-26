using BusinessLogic.Domain.Plan;

namespace BusinessLogic.Domain;

public enum Gender
{
    male,
    female
};
public class User : BaseEntity
{
    public User()
    {
        Rooms = new HashSet<Room>();
        FollowedUsers = new HashSet<User>();
        Followers = new HashSet<User>();
        Hubs = new HashSet<Hub>();
        Channels = new HashSet<Channel>();
        Posts = new HashSet<Post>();
        Announcements = new HashSet<Announcement>();
        Plans = new List<Plan.Plan>();
    }
    public User(string name, string email, string password, string username, Gender gender)
    {
        Rooms = new HashSet<Room>();
        FollowedUsers = new HashSet<User>();
        Followers = new HashSet<User>();
        Hubs = new HashSet<Hub>();
        Channels = new HashSet<Channel>();
        Posts = new HashSet<Post>();
        Announcements = new HashSet<Announcement>();
        Plans = new List<Plan.Plan>();

        Name = name;
        Email = email;
        Password = password;
        UserName = username;
        Gender = gender;
    }

    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public Gender Gender { get; set; }
    public byte[]? ProfilePicture { get; set; }
    public virtual ICollection<Room>? Rooms { get; set; }
    public virtual ICollection<Channel> Channels { get; set; }
    public virtual ICollection<Hub> Hubs { get; set; }
    public virtual ICollection<Post> Posts { get; set; }
    public virtual ICollection<Announcement> Announcements { get; set; }
    public virtual ICollection<Plan.Plan> Plans { get; set; }
    public virtual ICollection<User>? Followers { get; set; }
    public virtual ICollection<User>? FollowedUsers { get; set; }
}