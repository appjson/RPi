package main

import (
    "bufio"
    "compress/zlib"
    "crypto/md5"
    "crypto/tls"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "math/rand"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "os"
    "os/signal"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"
)

const (
    ApiUrl = "https://api.live.bilibili.com"

    FeedLiveApi = "https://api.live.bilibili.com/relation/v1/feed/feed_list"

    HistoryApi = "https://api.live.bilibili.com/room/v1/Room/room_entry_action"

    RoomInitApi  = "https://api.live.bilibili.com/room/v1/Room/room_init"
    CheckRoomApi = "https://api.live.bilibili.com/xlive/lottery-interface/v1/lottery/Check"

    PkJoinApi    = "https://api.live.bilibili.com/xlive/lottery-interface/v2/pk/join"
    GuardJoinApi = "https://api.live.bilibili.com/xlive/lottery-interface/v3/guard/join"
    GiftJoinApi  = "https://api.live.bilibili.com/xlive/lottery-interface/v5/smalltv/join"

    PassportSsoApi     = "https://passport.bilibili.com/api/login/sso"
    PassportRefreshApi = "https://passport.bilibili.com/api/login/renewToken"
)

type FeedJson struct {
    Data struct {
        List []struct {
            Roomid int `json:"roomid"`
        } `json:"list"`
    } `json:"data"`
}

type RoomInitJson struct {
    Data struct {
        RoomID    int  `json:"room_id"`
        IsHidden  bool `json:"is_hidden"`
        IsLocked  bool `json:"is_locked"`
        Encrypted bool `json:"encrypted"`
    } `json:"data"`
}

type RoomCheckJson struct {
    Data struct {
        Pk []struct {
            Id       int `json:"id"`
            TimeWait int `json:"time_wait"`
        } `json:"pk"`
        Guard []struct {
            Id       int    `json:"id"`
            Keyword  string `json:"keyword"`
            TimeWait int    `json:"time_wait"`
        } `json:"guard"`
        Gift []struct {
            Raffleid int    `json:"raffleid"`
            Type     string `json:"type"`
            TimeWait int    `json:"time_wait"`
        } `json:"gift"`
    } `json:"data"`
}

type AwardJson struct {
    Code int `json:"code"`
    Data struct {
        AwardNum  int    `json:"award_num"`
        AwardName string `json:"award_name"`
        AwardText string `json:"award_text"`
    } `json:"data"`
}

type MessageJson struct {
    Cmd        string `json:"cmd"`
    MsgType    int    `json:"msg_type"`
    Roomid     int    `json:"roomid"`
    RealRoomid int    `json:"real_roomid"`
}

type WSS struct {
    BufReader *bufio.Reader
    BufWriter *bufio.Writer
}

type BilibiliConnection struct {
    RoomID          int
    Uid             int
    ProtocolVersion uint16
    Connected       bool
    Connection      *WSS
    Lock            sync.Mutex

    Helper *BilibiliHelper
}

type BilibiliHelper struct {
    Uid       int
    AccessKey string
    Csrf      string
    Client    *http.Client

    OpenTab    map[int]bool
    PendingTab chan int
    ClosingTab chan int
}

func FatalIfErrorNotNil(err error) {
    if err != nil {
        log.Fatalf("Error: %s", err)
    }
}

func DialWSS() (*WSS, error) {
    var wss WSS
    if c, err := tls.Dial("tcp", "broadcastlv.chat.bilibili.com:443", nil); err != nil {
        return nil, err
    } else {
        wss.BufReader = bufio.NewReader(c)
        wss.BufWriter = bufio.NewWriter(c)
    }

    headers := map[string]string{
        "Upgrade":               "websocket",
        "Connection":            "Upgrade",
        "Sec-WebSocket-Key":     "6Znndtur+9SH12v1ck28mA==",
        "Origin":                "https://live.bilibili.com",
        "Sec-WebSocket-Version": "13",
    }
    req, _ := http.NewRequest("GET", "wss://broadcastlv.chat.bilibili.com/sub", nil)
    for k, v := range headers {
        req.Header.Set(k, v)
    }

    _ = req.Write(wss.BufWriter)
    if err := wss.BufWriter.Flush(); err != nil {
        return nil, err
    }

    if _, err := http.ReadResponse(wss.BufReader, nil); err != nil {
        return nil, err
    }
    return &wss, nil
}

func (wss *WSS) SendMessage(frameType byte, msg []byte) error {
    var (
        header       = make([]byte, 2, 10)
        b            = 0x80 | frameType
        length       = len(msg)
        lengthFields int
    )
    header[0] = b
    switch {
    case length <= 125:
        b = byte(length)
    case length <= 65535:
        b = 126
        lengthFields = 2
    default:
        b = 127
        lengthFields = 8
    }
    header[1] = b
    header = header[:lengthFields+2]
    switch lengthFields {
    case 2:
        binary.BigEndian.PutUint16(header[2:], uint16(length))
    case 8:
        binary.BigEndian.PutUint64(header[2:], uint64(length))
    }
    _, _ = wss.BufWriter.Write(header)
    _, _ = wss.BufWriter.Write(msg)
    return wss.BufWriter.Flush()
}

func (wss *WSS) ReadMessage() (io.Reader, error) {
    var (
        header       = make([]byte, 2, 10)
        b            byte
        length       int64
        lengthFields int
    )
    if _, err := io.ReadFull(wss.BufReader, header); err != nil {
        return nil, err
    }

    b = header[1]
    switch {
    case b <= 125:
        length = int64(b)
    case b == 126:
        lengthFields = 2
    case b == 127:
        lengthFields = 8
    }
    header = header[:lengthFields+2]
    if _, err := io.ReadFull(wss.BufReader, header[2:]); err != nil {
        return nil, err
    }

    switch lengthFields {
    case 2:
        length = int64(binary.BigEndian.Uint16(header[2:]))
    case 8:
        length = int64(binary.BigEndian.Uint64(header[2:]))
    }
    return io.LimitReader(wss.BufReader, length), nil
}

func NewConn(roomID, uid int, helper *BilibiliHelper) *BilibiliConnection {
    return &BilibiliConnection{
        RoomID:          roomID,
        Uid:             uid,
        ProtocolVersion: 2,
        Helper:          helper,
    }
}

func (conn *BilibiliConnection) SendData(action uint32, body []byte) error {
    var (
        pLen = uint32(len(body) + 16)
        msg  = make([]byte, pLen)
    )
    binary.BigEndian.PutUint32(msg[:4], pLen)
    binary.BigEndian.PutUint16(msg[4:6], 16)
    binary.BigEndian.PutUint16(msg[6:8], conn.ProtocolVersion)
    binary.BigEndian.PutUint32(msg[8:12], action)
    binary.BigEndian.PutUint32(msg[12:16], 1)
    copy(msg[16:], body)
    return conn.Connection.SendMessage(2, msg)
}

func (conn *BilibiliConnection) SendJoin() error {
    payload, _ := json.Marshal(map[string]int{
        "roomid":   conn.RoomID,
        "uid":      conn.Uid,
        "protover": int(conn.ProtocolVersion),
    })
    return conn.SendData(7, payload)
}

func (conn *BilibiliConnection) Disconnect() {
    conn.Lock.Lock()
    if conn.Connected {
        msg := make([]byte, 2)
        binary.BigEndian.PutUint16(msg, 1000)
        conn.Connected = false
        _ = conn.Connection.SendMessage(8, msg)
    }
    conn.Lock.Unlock()
}

func (conn *BilibiliConnection) HandleMessage(message io.Reader) {
    var messageJson MessageJson
    _ = json.NewDecoder(message).Decode(&messageJson)

    switch messageJson.Cmd {
    case "NOTICE_MSG":
        switch messageJson.MsgType {
        case 2, 3, 8:
            if messageJson.RealRoomid != 0 {
                conn.Helper.PendingTab <- messageJson.RealRoomid
            }
        }
    case "GUARD_MSG":
        if messageJson.Roomid != 0 {
            conn.Helper.PendingTab <- messageJson.Roomid
        }
    }
}

func (conn *BilibiliConnection) CheckLoop() {
    var (
        decoded RoomCheckJson
        wg      sync.WaitGroup

        pkMap    = make(map[int]bool)
        guardMap = make(map[int]bool)
        giftMap  = make(map[int]bool)
    )
    for conn.Connected {
        for k := range pkMap {
            delete(pkMap, k)
        }
        for k := range guardMap {
            delete(guardMap, k)
        }
        for k := range giftMap {
            delete(giftMap, k)
        }

        for i := 0; i < 2; i++ {
            resp, err := conn.Helper.Get(CheckRoomApi, map[string]string{
                "roomid": strconv.Itoa(conn.RoomID),
            })
            if err != nil {
                continue
            }

            _ = json.NewDecoder(resp.Body).Decode(&decoded)
            _ = resp.Body.Close()

            for _, pk := range decoded.Data.Pk {
                pk := pk
                if _, ok := pkMap[pk.Id]; !ok {
                    pkMap[pk.Id] = true
                    wg.Add(1)
                    time.AfterFunc(time.Duration(pk.TimeWait)*time.Second, func() {
                        conn.Helper.Join(pk.Id, conn.RoomID, "pk", PkJoinApi)
                        wg.Done()
                    })
                }
            }
            for _, guard := range decoded.Data.Guard {
                guard := guard
                if _, ok := guardMap[guard.Id]; !ok {
                    guardMap[guard.Id] = true
                    wg.Add(1)
                    time.AfterFunc(time.Duration(guard.TimeWait)*time.Second, func() {
                        conn.Helper.Join(guard.Id, conn.RoomID, guard.Keyword, GuardJoinApi)
                        wg.Done()
                    })
                }
            }
            for _, gift := range decoded.Data.Gift {
                gift := gift
                if _, ok := giftMap[gift.Raffleid]; !ok {
                    giftMap[gift.Raffleid] = true
                    wg.Add(1)
                    time.AfterFunc(time.Duration(gift.TimeWait)*time.Second, func() {
                        conn.Helper.Join(gift.Raffleid, conn.RoomID, gift.Type, GiftJoinApi)
                        wg.Done()
                    })
                }
            }
            if i != 1 {
                time.Sleep(30 * time.Second)
            }
        }

        wg.Wait()
        if len(pkMap) == 0 && len(guardMap) == 0 && len(giftMap) == 0 {
            conn.Disconnect()
        }
    }
}

func (conn *BilibiliConnection) HeartbeatLoop() {
    for conn.Connected {
        if err := conn.SendData(2, nil); err != nil {
            conn.Disconnect()
            break
        }
        time.Sleep(30 * time.Second)
    }
}

func (conn *BilibiliConnection) MessageLoop() {
    var (
        header     = make([]byte, 16)
        zlibReader io.ReadCloser
    )
    for conn.Connected {
        message, err := conn.Connection.ReadMessage()
        if err != nil {
            conn.Disconnect()
            break
        }

        _, _ = io.ReadFull(message, header)
        ver := binary.BigEndian.Uint16(header[6:8])
        action := binary.BigEndian.Uint32(header[8:12])

        if action == 5 {
            if ver == 2 {
                if zlibReader != nil {
                    _ = zlibReader.(zlib.Resetter).Reset(message, nil)
                } else {
                    zlibReader, _ = zlib.NewReader(message)
                }
                for zlibReader != nil {
                    if _, err = io.ReadFull(zlibReader, header); err != nil {
                        _ = zlibReader.Close()
                        break
                    }
                    conn.HandleMessage(io.LimitReader(zlibReader, int64(binary.BigEndian.Uint32(header[:4])-16)))
                }
            } else {
                conn.HandleMessage(message)
            }
        }
        _, _ = io.Copy(ioutil.Discard, message)
    }
}

func (conn *BilibiliConnection) Connect(checkRoom bool) {
    if roomID, ok := conn.Helper.GetRoomInit(conn.RoomID); !ok {
        return
    } else {
        conn.RoomID = roomID
    }

    if wss, err := DialWSS(); err != nil {
        return
    } else {
        conn.Connection = wss
    }

    if err := conn.SendJoin(); err != nil {
        return
    }
    conn.Connected = true

    if checkRoom {
        go conn.CheckLoop()
    }
    go conn.HeartbeatLoop()
    conn.MessageLoop()
}

func NewHelper(uid int, accessKey string) *BilibiliHelper {
    cookieJar, _ := cookiejar.New(nil)
    helper := &BilibiliHelper{
        Uid:       uid,
        AccessKey: accessKey,
        Client: &http.Client{
            Jar: cookieJar,
        },
        OpenTab:    make(map[int]bool),
        PendingTab: make(chan int, 5),
        ClosingTab: make(chan int, 5),
    }

    params := make(map[string]string)
    helper.Sign(params)
    _, err := helper.Get(PassportSsoApi, params)
    FatalIfErrorNotNil(err)

    cookieUrl, _ := url.Parse(ApiUrl)
    for _, c := range cookieJar.Cookies(cookieUrl) {
        if c.Name == "bili_jct" {
            helper.Csrf = c.Value
        }
    }

    _, err = helper.Get(PassportRefreshApi, params)
    FatalIfErrorNotNil(err)

    return helper
}

func (helper *BilibiliHelper) Sign(params map[string]string) {
    var (
        AppKey    = "1d8b6e7d45233436"
        AppSecret = "560c52ccd288fed045859ed18bffd973"
        hash      = md5.New()
        keys      = make([]string, 0, len(params)+7)
    )
    params["appkey"] = AppKey
    params["ts"] = strconv.FormatInt(time.Now().Unix(), 10)
    params["access_key"] = helper.AccessKey
    params["build"] = "8230"
    params["device"] = "phone"
    params["mobi_app"] = "iphone"
    params["platform"] = "ios"
    for k, v := range params {
        keys = append(keys, fmt.Sprintf("%s=%s", k, v))
    }
    sort.Strings(keys)
    _, _ = io.WriteString(hash, strings.Join(keys, "&"))
    _, _ = io.WriteString(hash, AppSecret)
    params["sign"] = hex.EncodeToString(hash.Sum(nil))
}

func (helper *BilibiliHelper) Get(urlString string, params map[string]string) (*http.Response, error) {
    req, _ := http.NewRequest("GET", urlString, nil)
    q := req.URL.Query()
    for k, v := range params {
        q.Add(k, v)
    }
    req.URL.RawQuery = q.Encode()

    return helper.Client.Do(req)
}

func (helper *BilibiliHelper) GetRoomInit(roomID int) (int, bool) {
    resp, err := helper.Get(RoomInitApi, map[string]string{
        "id": strconv.Itoa(roomID),
    })
    if err != nil {
        return 0, false
    }

    var decoded RoomInitJson
    _ = json.NewDecoder(resp.Body).Decode(&decoded)
    _ = resp.Body.Close()

    if decoded.Data.IsHidden || decoded.Data.IsLocked || decoded.Data.Encrypted {
        return decoded.Data.RoomID, false
    } else {
        return decoded.Data.RoomID, true
    }
}

func (helper *BilibiliHelper) PostWatchHistory(roomID int) {
    payload := url.Values{
        "room_id":    []string{strconv.Itoa(roomID)},
        "platform":   []string{"pc"},
        "csrf_token": []string{helper.Csrf},
        "csrf":       []string{helper.Csrf},
    }
    _, _ = helper.Client.PostForm(HistoryApi, payload)
}

func (helper *BilibiliHelper) Join(id, roomID int, typeString, apiString string) {
    payload := url.Values{
        "id":         []string{strconv.Itoa(id)},
        "roomid":     []string{strconv.Itoa(roomID)},
        "type":       []string{typeString},
        "csrf_token": []string{helper.Csrf},
        "csrf":       []string{helper.Csrf},
        "visit_id":   []string{""},
    }
    resp, err := helper.Client.PostForm(apiString, payload)
    if err != nil {
        return
    }

    var decoded AwardJson
    _ = json.NewDecoder(resp.Body).Decode(&decoded)
    _ = resp.Body.Close()

    if decoded.Code == 0 {
        switch apiString {
        case PkJoinApi:
            typeString = "pk"
        case GuardJoinApi:
            typeString = "guard"
        case GiftJoinApi:
            typeString = "gift"
        }

        if decoded.Data.AwardText != "" {
            log.Printf("房间%d领取%s奖品: %s", roomID, typeString, decoded.Data.AwardText)
        } else {
            log.Printf("房间%d领取%s奖品: %sX%d", roomID, typeString, decoded.Data.AwardName, decoded.Data.AwardNum)
        }
    }
}

func (helper *BilibiliHelper) HandleRoom(roomID int) {
    conn := NewConn(roomID, helper.Uid, helper)
    helper.PostWatchHistory(roomID)
    conn.Connect(true)
    helper.ClosingTab <- roomID
}

func (helper *BilibiliHelper) HandleTab() {
    var (
        sigChan     = make(chan os.Signal, 1)
        interrupted = false
    )
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    for {
        select {
        case p := <-helper.PendingTab:
            if _, ok := helper.OpenTab[p]; !ok && !interrupted {
                helper.OpenTab[p] = true
                go helper.HandleRoom(p)
            }
        case c := <-helper.ClosingTab:
            delete(helper.OpenTab, c)
            if len(helper.OpenTab) == 0 && interrupted {
                os.Exit(0)
            }
        case <-sigChan:
            interrupted = true
            if len(helper.OpenTab) == 0 {
                os.Exit(0)
            }
        }
    }
}

func (helper *BilibiliHelper) Connect() {
    rand.Seed(time.Now().Unix())

    var (
        decoded FeedJson
        roomID  int
    )
    for {
        resp, err := helper.Get(FeedLiveApi, nil)
        if err != nil {
            time.Sleep(30 * time.Second)
            continue
        }

        _ = json.NewDecoder(resp.Body).Decode(&decoded)
        _ = resp.Body.Close()

        roomID = decoded.Data.List[rand.Intn(len(decoded.Data.List))].Roomid
        conn := NewConn(roomID, helper.Uid, helper)
        helper.PostWatchHistory(roomID)

        time.AfterFunc(20*time.Minute, func() {
            conn.Disconnect()
        })
        conn.Connect(false)
    }
}

func main() {
    accessKey := "d865d65110c2c8992f691c785a03cb61"

    helper := NewHelper(0, accessKey)

    go helper.HandleTab()
    helper.Connect()
}
