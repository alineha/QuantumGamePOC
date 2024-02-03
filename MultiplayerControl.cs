using Godot;
using Newtonsoft.Json;
using OpenQuantumSafe;
using quantum;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

public partial class MultiplayerControl : Control
{
    [Export]
    private int port = 8910;

    [Export]
    private string address = "127.0.0.1";

    private goquantumsafe quantum = new goquantumsafe();

    private ENetMultiplayerPeer peer;

    public byte[] publicKey;

    public Dictionary<int, byte[]> othersPublicKey = new Dictionary<int, byte[]>();

    private byte[] privateKey;

    private Dictionary<int, byte[]> sharedSecret = new Dictionary<int, byte[]>();

    private string kemType = "Kyber512";

    private KEM kem;

    private List<Player> playerList = new List<Player>();

    private AesContext _aes = new AesContext();

    public override void _Ready()
    {
        Multiplayer.PeerConnected += PeerConnected;
        Multiplayer.PeerDisconnected += PeerDisconnected;
        Multiplayer.ConnectedToServer += ConnectedToServer;
        Multiplayer.ConnectionFailed += ConnectionFailed;
        if (OS.GetCmdlineArgs().Contains("--server"))
        {
            hostGame();
        }
    }

    private void ConnectionFailed()
    {
        GD.Print("CONNECTION FAILED");
    }

    private void ConnectedToServer()
    {
        GD.Print("Connected To Server");
        keyEncapsulationMechanism();
    }

    public void sendPlayer()
    {
        Player player = new Player()
        {
            Name = GetNode<LineEdit>("Username").Text,
            Password = GetNode<LineEdit>("Password").Text,
            Id = Multiplayer.GetUniqueId()
        };


        _aes.Start(AesContext.Mode.EcbEncrypt, sharedSecret[1]);
        byte[] byteArray = quantum.ObjectToByteArray(player); 
        int length = byteArray.Length;
        quantum.PadToMultipleOf(ref byteArray, 16);
        byte[] encryptedPlayer = _aes.Update(byteArray);
        _aes.Finish();

        _aes.Start(AesContext.Mode.EcbEncrypt, sharedSecret[1]);
        byte[] len = BitConverter.GetBytes(length);
        quantum.PadToMultipleOf(ref len, 16);
        byte[] encryptedLen = _aes.Update(len);
        _aes.Finish();

        RpcId(1, "receivePlayer", encryptedPlayer, encryptedLen);
    }

    private void PeerDisconnected(long id)
    {
        GD.Print("Player Disconnected: " + id.ToString());
    }

    private void PeerConnected(long id)
    {
        GD.Print("Player Connected! " + id.ToString());
    }

    public override void _Process(double delta)
    {
    }

    private void hostGame()
    {
        setKeys();

        peer = new ENetMultiplayerPeer();
        var error = peer.CreateServer(port, 2);
        if (error != Error.Ok)
        {
            GD.Print("error cannot host! :" + error.ToString());
            return;
        }
        peer.Host.Compress(ENetConnection.CompressionMode.RangeCoder);

        Multiplayer.MultiplayerPeer = peer;
        GD.Print("Waiting For Players!");
    }

    public void _on_host_button_down()
    {
        hostGame();
    }

    public void _on_join_button_down()
    {
        peer = new ENetMultiplayerPeer();
        peer.CreateClient(address, port);

        peer.Host.Compress(ENetConnection.CompressionMode.RangeCoder);
        Multiplayer.MultiplayerPeer = peer;
        GD.Print("Joining Game!");
    }
    public void _on_start_game_button_down()
    {
        Rpc("startGame");
    }

    [Rpc(MultiplayerApi.RpcMode.AnyPeer, CallLocal = true, TransferMode = MultiplayerPeer.TransferModeEnum.Reliable)]
    private void startGame()
    {

        var scene = ResourceLoader.Load<PackedScene>("res://TestScene.tscn").Instantiate<Node2D>();
        GetTree().Root.AddChild(scene);
        this.Hide();
    }

    [Rpc(MultiplayerApi.RpcMode.AnyPeer)]
    private void receivePlayer(byte[] playerEncrypted, byte[] lengthEncrypted)
    {
        int id = Multiplayer.GetRemoteSenderId();
        _aes.Start(AesContext.Mode.EcbDecrypt, sharedSecret[id]);
        byte[] lengthDecrypted = _aes.Update(lengthEncrypted);
        _aes.Finish();
        Array.Resize(ref lengthDecrypted, 4);
        int length = BitConverter.ToInt32(lengthDecrypted, 0);

        _aes.Start(AesContext.Mode.EcbDecrypt, sharedSecret[id]);
        byte[] playerDecrypted = _aes.Update(playerEncrypted);
        _aes.Finish();
        quantum.Unpad(ref playerDecrypted, length);
        string str = Encoding.ASCII.GetString(playerDecrypted);
        Player player = JsonConvert.DeserializeObject<Player>(str);

        playerList.Add(player);
        GD.Print(JsonConvert.SerializeObject(player));
    }

    [Rpc(MultiplayerApi.RpcMode.AnyPeer)]
    private void keyEncapsulationMechanism() // CLIENT
    {
        if (publicKey == null)
        {
            setKeys(); // client generates its key pair
            RpcId(1, "receiveKey", publicKey); // sends the public key to server
        }
    }

    private void setKeys()
    {
        kem = quantum.SetKEM(kemType);
        quantum.GetKeys(kem, out publicKey, out privateKey);
    }

    [Rpc(MultiplayerApi.RpcMode.AnyPeer)]
    private void receiveKey(byte[] key) // SERVER
    {
        int id = Multiplayer.GetRemoteSenderId();
        othersPublicKey.Add(id, key); // receives client's public key

        byte[] ciphertext;
        byte[] secret;
        quantum.Encapsulate(kem, out ciphertext, out secret, key); // generates and encapsulates the shared secret

        sharedSecret.Add(id, secret);
        GD.Print("Secret server:" + string.Join(", ", secret));

        RpcId(id, "receiveCiphertext", ciphertext); // sends the shared secret to the client
    }

    [Rpc(MultiplayerApi.RpcMode.AnyPeer)]
    private void receiveCiphertext(byte[] ciphertext)
    {
        byte[] secret;
        quantum.Decapsulate(kem, ciphertext, out secret, privateKey); // the client gets the shared secret from the ciphertext
        sharedSecret.Add(1, secret); // now they have a shared secret that matches
        GD.Print("Secret client:" + string.Join(", ", secret));
        sendPlayer();
    }
}
