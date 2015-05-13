[![Build Status](https://travis-ci.org/KLab/miruo.svg?branch=master)](https://travis-ci.org/KLab/miruo)

# はじめに
  miruo はパケットキャプチャ型の TCP セッションモニタです。
  以下のような特徴があります。

  - TCP セッション単位でパケットをまとめて表示できます
  - TCP の接続、切断部分のみをコンパクトに表示できます
  - セグメントが再送された TCP セッションを発見できます
  - 通信に時間がかかった TCP セッションを発見できます
  - RST で中断された TCP セッションを発見できます
  - IP でフラグメントされたセグメントを発見できます
  - tcpdump の -w で保存されたファイルを利用できます
  - 軽量で高速に動作します

## インストール方法

    $ tar zxvf miruo-x.y.z.tar.gz
    $ cd miruo-x.y.z
    $ ./configure
    $ make
    $ sudo make install

# 使い方

    usage: miruo [option] [expression]

    option
      -h, --help                     # help
      -V, --version                  # version
      -i, --interface=dev            # eth0,bond0,any...
      -v, --view-data=NUM            #
      -T, --long-connect=time[ms]    # Threshold of connection time for lookup. Default 0ms(off)
      -t, --long-delay=time[ms]      # Threshold of long delay time for lookup. Default 0ms(off)
      -r, --retransmit=time[ms]      # Threshold of retransmit time for lookup. Default 1000ms
      -s, --stat=interval[sec]       # statistics view interval. Default 0sec(off)
      -f, --file=file                # read file(for tcpdump -w)
      -S, --syn=[0|1]                # syn retransmit lookup mode.default=1. 0=ignore 1=lookup
      -R, --rst=[0|1|2]              # rst lookup mode.default=1. (see README)
      -F, --flagment=[0|1]           # ip flagment lookup. default=1
      -C, --color=[0|1]              # color 0=off 1=on
      -L, --session-limit=NUM        # active session limit. Default 1024
      -l, --segment-limit=NUM        # active segment limit. Default 65536
      -m, --dpi-mode=mode            # deep packet inspection mode. (now support only http)
      -q, --qiute                    #
          --all                      # all session lookup
          --live                     # live mode(all segment lookup)

`expression` には tcpdump と同じ書式でフィルタを記述できます。

ただし、`tcp[13] & 2 != 0` などのような、TCP の一部のパケットのみを抽出するルールを書いてしまうと、TCP セッションを追跡できなくなるので注意してください。フィルタの書式については tcpdump の man を参照してください。

**良い例**

    # miruo -T3000 host dbserver and port 3306

  *MySQL に3秒以上接続しているセッションを表示します*

**悪い例**

    # miruo -T3000 dst host dbserver and dst port 3306

  *SYN/ACK などをキャプチャできないので TCP を追跡できなくなります*

## オプションの詳細

<dl>
  <dt>-h, --help</dt>
  <dd>ヘルプを表示します。</dd>

  <dt>-V, --version</dt>
  <dd>バージョンを表示します。</dd>

  <dt> -i, --interface=dev</dt>
  <dd>ネットワークインターフェイスを指定します。
  <code>any</code> も指定できます。</dd>

  <dt>-v, --view-data=NUM</dt>
  <dd>この値が <code>0</code> の場合は、再送や遅延したパケットと、接続や切断に関するパケットのみを表示します。
  <code>0</code> 以外の値を指定すると、指定された数だけ他のパケットも表示されるようになります。
  デフォルト値は <code>0</code> です。</dd>

  <dt>-T, --long-connect=time[ms]</dt>
  <dd>接続から切断までの時間が、ここで指定した時間以上だったセッションを表示するように指示します。
  デフォルト値は <code>0</code> で、接続時間による抽出は行いません。</dd>

  <dt>-t, --long-delay=time[ms]</dt>
  <dd>ここで指定した時間よりも、長い時間をかけて到達したパケットを発見します。
  デフォルト値は <code>0</code> で、到達時間による抽出は行いません。</dd>

  <dt>-r, --retransmit=time[ms]</dt>
  <dd><code>0</code> を指定すると、再送されたTCPセグメントを無視します。
  <code>0</code> 以外の値を指定すると、指定された時間（ミリ秒単位）以上の時間をかけて再送されたセグメントを表示します。
  デフォルトは <code>1000</code>（ミリ秒）です。</dd>

  <dt>-s, --stat=interval[sec]</dt>
  <dd>定期的にstderrへ統計情報を出力します。
  デフォルト値は <code>0</code> で、統計情報を表示しません。</dd>

  <dt>-f, --file=file</dt>
  <dd><code>tcpdump -w</code> で保存したファイルを利用したい時にファイル名を指定してください。</dd>

  <dt>-S, --syn=[0|1]</dt>
  <dd>
    SYN もしくは SYN/ACK の再送を検出するかどうかを指定します。<br/>
    <ul>
      <li><strong>0:</strong> 検出しません</li>
      <li><strong>1:</strong> 検出します</li>
    </ul>
    SYN と SYN/ACK の再送検出は、<code>-r</code> オプションとは独立して処理されます。
    <code>-r</code> オプションの指定内容に関わらず、ここで <code>1</code> を指定すると再送を検出しますし、<code>0</code> を指定すると検出しなくなります。
  </dd>

  <dt>-R, --rst=[0|1|2]</dt>
  <dd>
    RST フラグで中断されたセッションを検出するかどうかを指定します。<br/>
    <ul>
      <li><strong>0:</strong> 検出しません</li>
      <li><strong>1:</strong> 検出はしますが、FINを送った後のRSTは検出しません</li>
      <li><strong>2:</strong> 全てのRSTを検出します</li>
    </ul>
    デフォルト値は <code>1</code> です。
  </dd>

  <dt>-F, --flagment=[0|1]</dt>
  <dd>
    IP フラグメントを検出するかどうか指定します。<br/>
    <ul>
      <li><strong>0:</strong> 検出しません</li>
      <li><strong>1:</strong> 検出します</li>
    </ul>
    デフォルト値は <code>1</code> です。
  </dd>

  <dt>-C, --color=[0|1]</dt>
  <dd>カラー表示をしたくない場合は <code>0</code> を指定してください。
  デフォルトは <code>1</code> ですが、標準出力をファイルに落とす場合や、パイプで他のコマンドに渡す場合は <code>0</code> になります。
  パイプで grep などに渡したいけど、カラー表示をしたいような時には明示的に <code>1</code> を指定してください</dd>

  <dt>-L, --session-limit=NUM</dt>
  <dd>同時に保持できるセッション数を指定します。
  これは、miruo の内部バッファの最大値を指定するオプションで、意図せずに大量のメモリ（サーバリソース）を使い過ぎないように制限するためのものです。
  デフォルト値は <code>1024</code> ですが、統計情報（後述）の <code>DropSession</code> の項目が <code>0</code> ならば増やす必要はないでしょう。</dd>

  <dt>-l, --segment-limit=NUM</dt>
  <dd>同時に保持できるセグメント数を指定します。
  これは、miruo の内部バッファの最大値を指定するオプションで、意図せずに大量のメモリ（サーバリソース）を使い過ぎないように制限するためのものです。
  デフォルト値は <code>65536</code> ですが、統計情報（後述）の <code>DropSegment</code> の項目が <code>0</code> ならば増やす必要はないでしょう。</dd>

  <dt>-m, --dpi-mode=mode</dt>
  <dd>
    TCP セグメントのペイロードを解析してプロトコル固有の情報を表示したい場合は以下のモード（プロトコル名）を指定します。<br/>
    <ul>
      <li><strong>http:</strong> HTTPリクエスト・レスポンスの情報を表示します</li>
    </ul>
  </dd>

  <dt>-q, --qiute</dt>
  <dd>シンプルな表示になります。
  横幅が <code>80</code> 文字以内じゃないと我慢出来ない場合に指定するとよいかもです。</dd>

  <dt>--all</dt>
  <dd>すべてのセッションを表示します。</dd>

  <dt>--live</dt>
  <dd>すべてのパケットをリアルタイムに表示します。</dd>
</dl>

## 統計情報

`-s` オプションを指定すると、定期的に `stderr` へ統計情報を出力するようになります。
各項目の意味は以下のとおりです。

    ===== Session Statistics =====
    Captcha Time    : 00:01:03     開始してからの経過時間
    Total Sessions  : 0            追跡したTCPセッションの数
      Lookup        : 0            表示したTCPセッションの数
        LongConnect : 0            LongConnectTimeを超えたセッションの数
        LongDelay   : 0            LongDelayTimeを超えたセッションの数
        Retransmit  : 0            再送が発生したセッションの数
        Timeout     : 0            タイムアウトしたセッションの数
        Error       : 0            追跡しきれなくてエラーになった数
        RST         : 0            RSTでリセットされたセッションの数
        flagment    : 0            IPフラグメントされたセッションの数
    ------------------------------
    LongConnectTime : 0 [ms]       -Tオプションの設定値
    LongDelayTime   : 0 [ms]       -tオプションの設定値
    RetransmitTime  : 1000 [ms]    -rオプションの設定値
    ------------------------------
    ActiveSession   : 0            現在追跡しているTCPセッションの数
    ActiveSessionMax: 0            同時に追跡したTCPセッションの最大数
    ActiveSessionLim: 1024         同時に追跡可能なTCPセッションの最大数(-Lオプションで指定)
    ActiveSegment   : 0            現在保持しているTCPセグメントの数
    ActiveSegmentMax: 0            同時に保持する必要があったセグメントの最大数
    ActiveSegmentLim: 65536        同時に保持可能なセグメントの最大数(-lオプションで指定)
    DropSession     : 0            保持しきれなくて捨ててしまったTCPセッションの数
    DropSegment     : 0            保持しきれなくて捨ててしまったTCPセグメントの数
    ------------------------------
    CPU   : 0.0%                   miruoのCPU使用率
    VSZ   : 6100KB                 miruoが確保した仮想メモリサイズ
    RSS   : 2932KB                 miruoが利用している物理メモリサイズ
    ===== libpcap Statistics =====
    recv  : 89                     libpcapがキャプチャできたパケット数
    drop  : 0                      libpcapがドロップしたパケット数
    ifdrop: 0                      インターフェイスがドロップしたパケット数
    ===== Header Error Count =====
    L2    : 0                      データリンク層のヘッダ解析に失敗した数
    IP    : 0                      IPヘッダの解析に失敗した数
    TCP   : 0                      TCPヘッダの解析に失敗した数
    ==============================


***表示結果の説明***

    -------------------------------------------------------------------------------
    3615             2.196 |  192.168.61.88:38001 == 192.168.56.136:3306  | Total 92 segments, 43278 bytes
    3615:0000 17:57:19.193 |          SYN_SENT >----S-> SYN_RECV          | 5C503355/00000000   74 - <mss=1460, sackOK, timestamp 898447130 0, wscale=7>
    3615:0001 17:57:19.193 |       ESTABLISHED <-A--S-< SYN_RECV          | 6BCBB846/5C503356   74 - <mss=1460, sackOK, timestamp 899636678 898447130, wscale=7>
    3615:0002 17:57:19.193 |       ESTABLISHED >-A----> ESTABLISHED       | 5C503356/6BCBB847   66 - <timestamp 898447130 899636678>
    3615:0003 17:57:19.193 |       ESTABLISHED <-AP---< ESTABLISHED       | 6BCBB847/5C503356  126 - <timestamp 899636678 898447130>
    3615:0004 17:57:19.193 |       ESTABLISHED >-A----> ESTABLISHED       | 5C503356/6BCBB883   66 - <timestamp 898447130 899636678>
    3615:0005 17:57:19.193 |       ESTABLISHED >-AP---> ESTABLISHED       | 5C503356/6BCBB883  150 - <timestamp 898447130 899636678>
    3615:****              |                                              |
    3615:0085 17:57:19.265 |       ESTABLISHED <-A----< ESTABLISHED       | 6BCC1685/5C505E8E 1514 - <timestamp 899636696 898447148>
    3615:0086 17:57:19.265 |       ESTABLISHED <-AP---< ESTABLISHED       | 6BCC1C2D/5C505E8E  687 - <timestamp 899636696 898447148>
    3615:0087 17:57:19.265 |       ESTABLISHED >-A----> ESTABLISHED       | 5C505E8E/6BCC1E9A   66 - <timestamp 898447148 899636696>
    3615:0088 17:57:21.389 |       ESTABLISHED >-AP---> ESTABLISHED       | 5C505E8E/6BCC1E9A   71 - <timestamp 898447679 899636696>
    3615:0089 17:57:21.389 |         FIN_WAIT1 >-A---F> ESTABLISHED       | 5C505E93/6BCC1E9A   66 - <timestamp 898447679 899636696>
    3615:0090 17:57:21.389 |         FIN_WAIT2 <-A---F< LAST_ACK          | 6BCC1E9A/5C505E94   66 - <timestamp 899637227 898447679>
    3615:0091 17:57:21.389 |         TIME_WAIT >-A----> CLOSED            | 5C505E94/6BCC1E9B   66 - <timestamp 898447679 899637227>
    -------------------------------------------------------------------------------

一番左の 3615 を、`セッションID` と呼びます。値自体には意味はなく、新しいTCPセッションが開始される度に miruo が内部でインクリメントして割り当てていきます。その隣のコロンで区切られた数値を `パケットID` と呼びます。最初の SYN を 0番とし、パケットが到着する度にインクリメントしていきます。`セッションID` と `パケットID` は、TCP や IP のプロトコルとは全く無関係なパラメータで、miruo の内部で利用している管理用の ID です。そのため、値自体は特別な意味を持ちませんが、上記の表示例の場合だと、

> 3615の88番のパケットが、到着するまでに2秒以上かかっているみたい

などと表現できるので、問題点を他の人と共有する際に便利だと思います。

次に表示しているのはパケットをキャプチャした時刻です。
先頭の行は接続時間（接続から切断までの経過時間）を表しており、この時間が `-T` オプションで指定した値を超えたセッションが表示されます。

中央の広い部分は、見ての通りなので説明は割愛します(^^;

`5C503355/00000000` や `6BCBB846/5C503356` はTCPヘッダのシーケンス番号/応答番号です。

74 とか 66 とか 1514 の数値はパケットサイズです。
環境によっては 1514 以上の値が表示される場合があるかもしれませんが、それはきっと、故障でもバグでもなく、`TOE（TCP Offload Engine）` の影響だと思います。

`-` と表示されている部分には、IP のフラグメントが発生している場合に `F` と表示されるようになります。`-F` オプションに <code>0</code> を指定すると、この項目は表示されません。

最後の `<>` で囲まれている部分は、TCP ヘッダのオプションです。

# ライセンス
Copyright (C) 2011-2015 KLab Inc.

このプログラムは `GNU General Public License version 3（GNU GPLv3）` の下で自由に配布することが出来ます。

`GNU GPLv3` の詳細は、http://www.gnu.org/licenses/gpl-3.0.txt をご覧ください。
