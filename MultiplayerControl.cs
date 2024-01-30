using Godot;
using OpenQuantumSafe;
using quantum;
using System;
using System.Collections.Generic;
using System.Linq;

public partial class MultiplayerControl : Control
{
    [Export]
    private int port = 8910;

    [Export]
    private string address = "127.0.0.1";

    private goquantumsafe quantum = new goquantumsafe();

    private ENetMultiplayerPeer peer;

    public byte[] publicKey;

    public IDictionary<int, byte[]> othersPublicKey = new Dictionary<int, byte[]>();

    private byte[] privateKey;

    private IDictionary<int, byte[]> sharedSecret = new Dictionary<int, byte[]>();

    private string kemType = "Kyber512";

    private KEM kem;

    private List<Player> playerList = new List<Player>();

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
        RpcId(1, "sendPlayer", GetNode<LineEdit>("Username").Text, GetNode<LineEdit>("Password").Text, Multiplayer.GetUniqueId());
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
        sendPlayer(GetNode<LineEdit>("Username").Text, GetNode<LineEdit>("Password").Text, 1);
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
    private void sendPlayer(string name, string password, int id)
    { // TODO edit this with KEM, securely store the password?
        Player player = new Player()
        {
            Name = name,
            Password = password,
            Id = id
        };

        playerList.Add(player);
    }

    [Rpc(MultiplayerApi.RpcMode.AnyPeer)]
    private void keyEncapsulationMechanism() // CLIENT
    {
        setKeys(); // client generates its key pair
        RpcId(1, "receiveKey", publicKey); // sends the public key to server
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
    }
}
