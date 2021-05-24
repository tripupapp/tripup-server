package notification

type Notification struct {
    signal  string
    silent  bool
}

type NotificationService interface {
    Notify([]string, Notification, *map[string]string) (error)
}

var (
    GroupInvite Notification = Notification{
        signal: "invitedToGroup",
        silent: false,
    }
    UserJoinedGroup Notification = Notification{
        signal: "userJoinedGroup",
        silent: false,
    }
    UserLeftGroup Notification = Notification{
        signal: "userLeftGroup",
        silent: true,
    }
    AssetsChangedForGroup Notification = Notification{
        signal: "assetsChangedForGroup",
        silent: true,
    }
    AssetsAddedToGroupByUser Notification = Notification{
        signal: "assetsAddedToGroupByUser",
        silent: false,
    }
)
