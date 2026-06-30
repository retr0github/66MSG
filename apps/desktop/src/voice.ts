import { useCallback, useEffect, useRef, useState } from "react";
import { Room, RoomEvent, Track } from "livekit-client";
import { apiBaseUrl, type Session } from "./auth";

export type VoiceConnectionState =
  | "idle"
  | "connecting"
  | "connected"
  | "error";

interface VoiceChat {
  readonly state: VoiceConnectionState;
  readonly muted: boolean;
  readonly deafened: boolean;
  readonly cameraEnabled: boolean;
  readonly cameraFeeds: readonly CameraFeed[];
  readonly screenSharing: boolean;
  readonly screenShareHasAudio: boolean;
  readonly audioPlaybackBlocked: boolean;
  readonly screenShares: readonly ScreenShare[];
  readonly participants: readonly VoiceParticipant[];
  readonly participantVoiceVolumes: Readonly<Record<string, number>>;
  readonly participantShareVolumes: Readonly<Record<string, number>>;
  readonly error: string | undefined;
  readonly join: () => Promise<void>;
  readonly leave: () => void;
  readonly toggleMute: () => Promise<void>;
  readonly toggleDeafen: () => Promise<void>;
  readonly toggleCamera: () => Promise<void>;
  readonly toggleScreenShare: (quality: ScreenShareQuality) => Promise<void>;
  readonly enableAudioPlayback: () => Promise<void>;
  readonly setParticipantVoiceVolume: (
    identity: string,
    volume: number,
  ) => void;
  readonly setParticipantShareVolume: (
    identity: string,
    volume: number,
  ) => void;
}

export type ScreenShareQuality =
  | "1080p60"
  | "1080p30"
  | "720p60"
  | "720p30";

export interface VoiceParticipant {
  readonly identity: string;
  readonly name: string;
  readonly muted: boolean;
  readonly speaking: boolean;
  readonly local: boolean;
}

export interface ScreenShare {
  readonly id: string;
  readonly identity: string;
  readonly name: string;
  readonly track: Track;
}

export interface CameraFeed {
  readonly id: string;
  readonly identity: string;
  readonly name: string;
  readonly local: boolean;
  readonly track: Track;
}

interface LiveKitTokenResponse {
  readonly server_url: string;
  readonly token: string;
  readonly room_name: string;
}

interface LiveKitParticipantsResponse {
  readonly participants: readonly {
    readonly identity: string;
    readonly name: string;
    readonly muted: boolean;
  }[];
}

export function useVoiceChat(
  session: Session,
  conversationId: string,
): VoiceChat {
  const roomRef = useRef<Room | undefined>(undefined);
  const deafenedRef = useRef(false);
  const mutedBeforeDeafenRef = useRef(false);
  const participantVoiceVolumesRef = useRef<Record<string, number>>({});
  const participantShareVolumesRef = useRef<Record<string, number>>({});
  const [state, setState] = useState<VoiceConnectionState>("idle");
  const [muted, setMuted] = useState(false);
  const [deafened, setDeafened] = useState(false);
  const [cameraEnabled, setCameraEnabled] = useState(false);
  const [cameraFeeds, setCameraFeeds] = useState<readonly CameraFeed[]>([]);
  const [screenSharing, setScreenSharing] = useState(false);
  const [screenShareHasAudio, setScreenShareHasAudio] = useState(false);
  const [audioPlaybackBlocked, setAudioPlaybackBlocked] = useState(false);
  const [screenShares, setScreenShares] = useState<readonly ScreenShare[]>([]);
  const [participants, setParticipants] = useState<
    readonly VoiceParticipant[]
  >([]);
  const [participantVoiceVolumes, setParticipantVoiceVolumes] = useState<
    Readonly<Record<string, number>>
  >({});
  const [participantShareVolumes, setParticipantShareVolumes] = useState<
    Readonly<Record<string, number>>
  >({});
  const [observedParticipants, setObservedParticipants] = useState<
    readonly VoiceParticipant[]
  >([]);
  const [error, setError] = useState<string>();

  const leave = useCallback(() => {
    const room = roomRef.current;
    roomRef.current = undefined;
    room?.disconnect();
    document
      .querySelectorAll<HTMLMediaElement>("[data-66msg-livekit-audio]")
      .forEach((element) => element.remove());
    setState("idle");
    setMuted(false);
    deafenedRef.current = false;
    mutedBeforeDeafenRef.current = false;
    setDeafened(false);
    setCameraEnabled(false);
    setCameraFeeds([]);
    setScreenSharing(false);
    setScreenShareHasAudio(false);
    setAudioPlaybackBlocked(false);
    setScreenShares([]);
    setParticipants([]);
    participantVoiceVolumesRef.current = {};
    participantShareVolumesRef.current = {};
    setParticipantVoiceVolumes({});
    setParticipantShareVolumes({});
    setError(undefined);
  }, []);

  useEffect(() => leave, [conversationId, leave]);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;

    const refresh = async () => {
      if (state !== "connected") {
        try {
          const query = new URLSearchParams({
            conversation_id: conversationId,
          });
          const response = await fetch(
            `${apiBaseUrl()}/livekit/participants?${query}`,
            {
              headers: { Authorization: `Bearer ${session.token}` },
            },
          );
          const body: unknown = await response.json().catch(() => undefined);
          if (
            active &&
            response.ok &&
            isLiveKitParticipantsResponse(body)
          ) {
            setObservedParticipants(
              body.participants.map((participant) => ({
                ...participant,
                speaking: false,
                local: participant.identity === session.user.id,
              })),
            );
          }
        } catch {
          // The next refresh will retry without interrupting the chat UI.
        }
      }
      if (active) timer = window.setTimeout(refresh, 2_000);
    };

    void refresh();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [conversationId, session.token, session.user.id, state]);

  const join = useCallback(async () => {
    if (roomRef.current !== undefined || state === "connecting") return;

    setState("connecting");
    setError(undefined);
    const room = new Room({
      adaptiveStream: true,
      dynacast: true,
    });
    roomRef.current = room;

    const updateParticipants = () => {
      setParticipants(
        [room.localParticipant, ...room.remoteParticipants.values()].map(
          (participant) => ({
            identity: participant.identity,
            name: participant.name ?? participant.identity,
            muted: !participant.isMicrophoneEnabled,
            speaking: participant.isSpeaking,
            local: participant.isLocal,
          }),
        ),
      );
    };

    room.on(RoomEvent.ParticipantConnected, updateParticipants);
    room.on(RoomEvent.ParticipantDisconnected, updateParticipants);
    room.on(RoomEvent.TrackPublished, updateParticipants);
    room.on(RoomEvent.TrackUnpublished, updateParticipants);
    room.on(RoomEvent.TrackMuted, updateParticipants);
    room.on(RoomEvent.TrackUnmuted, updateParticipants);
    room.on(RoomEvent.LocalTrackPublished, (publication) => {
      updateParticipants();
      if (
        publication.source === Track.Source.Camera &&
        publication.track !== undefined
      ) {
        setCameraEnabled(true);
        setCameraFeeds((current) => [
          ...current.filter((feed) => feed.identity !== session.user.id),
          {
            id: publication.trackSid,
            identity: session.user.id,
            name: session.user.username,
            local: true,
            track: publication.track!,
          },
        ]);
      }
      if (publication.source === Track.Source.ScreenShare) {
        setScreenSharing(true);
      }
      if (publication.source === Track.Source.ScreenShareAudio) {
        setScreenShareHasAudio(true);
      }
    });
    room.on(RoomEvent.LocalTrackUnpublished, (publication) => {
      updateParticipants();
      if (publication.source === Track.Source.Camera) {
        setCameraEnabled(false);
        setCameraFeeds((current) =>
          current.filter((feed) => feed.identity !== session.user.id),
        );
      }
      if (publication.source === Track.Source.ScreenShare) {
        setScreenSharing(false);
        setScreenShareHasAudio(false);
      }
      if (publication.source === Track.Source.ScreenShareAudio) {
        setScreenShareHasAudio(false);
      }
    });
    room.on(RoomEvent.ActiveSpeakersChanged, updateParticipants);
    room.on(RoomEvent.TrackSubscribed, (track, _publication, participant) => {
      if (
        track.kind === Track.Kind.Video &&
        track.source === Track.Source.ScreenShare
      ) {
        setScreenShares((current) => [
          ...current.filter((share) => share.track !== track),
          {
            id: track.sid ?? `${participant.identity}-screen`,
            identity: participant.identity,
            name: participant.name ?? participant.identity,
            track,
          },
        ]);
        return;
      }
      if (
        track.kind === Track.Kind.Video &&
        track.source === Track.Source.Camera
      ) {
        setCameraFeeds((current) => [
          ...current.filter((feed) => feed.identity !== participant.identity),
          {
            id: track.sid ?? `${participant.identity}-camera`,
            identity: participant.identity,
            name: participant.name ?? participant.identity,
            local: false,
            track,
          },
        ]);
        return;
      }
      if (track.kind === Track.Kind.Audio) {
        const volume =
          track.source === Track.Source.ScreenShareAudio
            ? (participantShareVolumesRef.current[participant.identity] ?? 100)
            : (participantVoiceVolumesRef.current[participant.identity] ??
              100);
        participant.setVolume(
          volume / 100,
          track.source === Track.Source.ScreenShareAudio
            ? Track.Source.ScreenShareAudio
            : Track.Source.Microphone,
        );
        const element = track.attach();
        element.dataset["66msgLivekitAudio"] = "true";
        element.dataset["66msgAudioSource"] = track.source;
        element.autoplay = true;
        element.volume = 1;
        element.muted = deafenedRef.current;
        document.body.appendChild(element);
        if (!deafenedRef.current) {
          void element.play().catch(() => setAudioPlaybackBlocked(true));
        }
      }
    });
    room.on(RoomEvent.TrackUnsubscribed, (track) => {
      track.detach().forEach((element) => element.remove());
      setScreenShares((current) =>
        current.filter((share) => share.track !== track),
      );
      setCameraFeeds((current) =>
        current.filter((feed) => feed.track !== track),
      );
    });
    room.on(RoomEvent.Disconnected, () => {
      if (roomRef.current === room) {
        roomRef.current = undefined;
        setState("idle");
        setParticipants([]);
        setCameraEnabled(false);
        setCameraFeeds([]);
        setScreenSharing(false);
        setScreenShareHasAudio(false);
        setAudioPlaybackBlocked(false);
        deafenedRef.current = false;
        mutedBeforeDeafenRef.current = false;
        setDeafened(false);
        setScreenShares([]);
      }
    });

    try {
      const response = await fetch(`${apiBaseUrl()}/livekit/token`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ conversation_id: conversationId }),
      });
      const body: unknown = await response.json().catch(() => undefined);
      if (!response.ok || !isLiveKitTokenResponse(body)) {
        throw new Error(readErrorMessage(body));
      }

      await room.connect(body.server_url, body.token);
      await room.localParticipant.setMicrophoneEnabled(true);
      await room.startAudio();
      updateParticipants();
      setMuted(false);
      setState("connected");
    } catch (reason) {
      roomRef.current = undefined;
      room.disconnect();
      setState("error");
      setError(
        reason instanceof Error
          ? reason.message
          : "Не удалось подключиться к голосовому чату",
      );
    }
  }, [conversationId, session.token, state]);

  const toggleMute = useCallback(async () => {
    const room = roomRef.current;
    if (room === undefined) return;
    if (deafenedRef.current) {
      setError(
        "Сначала отключите режим «Заглушить всех», чтобы включить микрофон",
      );
      return;
    }

    const nextMuted = !muted;
    try {
      await room.localParticipant.setMicrophoneEnabled(!nextMuted);
      setMuted(nextMuted);
      setParticipants(
        [room.localParticipant, ...room.remoteParticipants.values()].map(
          (participant) => ({
            identity: participant.identity,
            name: participant.name ?? participant.identity,
            muted: !participant.isMicrophoneEnabled,
            speaking: participant.isSpeaking,
            local: participant.isLocal,
          }),
        ),
      );
      setError(undefined);
    } catch {
      setError("Не удалось изменить состояние микрофона");
    }
  }, [muted]);

  const toggleCamera = useCallback(async () => {
    const room = roomRef.current;
    if (room === undefined) return;

    try {
      await room.localParticipant.setCameraEnabled(!cameraEnabled, {
        resolution: {
          width: 1280,
          height: 720,
          frameRate: 30,
        },
      });
      setCameraEnabled(room.localParticipant.isCameraEnabled);
      setError(undefined);
    } catch (reason) {
      if (
        reason instanceof DOMException &&
        (reason.name === "NotAllowedError" || reason.name === "AbortError")
      ) {
        setError("Доступ к камере не разрешён");
        return;
      }
      setError(
        reason instanceof Error ? reason.message : "Не удалось включить камеру",
      );
    }
  }, [cameraEnabled]);

  const toggleDeafen = useCallback(async () => {
    const room = roomRef.current;
    if (room === undefined) return;

    const nextDeafened = !deafenedRef.current;
    try {
      if (nextDeafened) {
        mutedBeforeDeafenRef.current = muted;
        await room.localParticipant.setMicrophoneEnabled(false);
        setMuted(true);
      } else if (!mutedBeforeDeafenRef.current) {
        await room.localParticipant.setMicrophoneEnabled(true);
        setMuted(false);
      }

      deafenedRef.current = nextDeafened;
      setDeafened(nextDeafened);
      document
        .querySelectorAll<HTMLMediaElement>("[data-66msg-livekit-audio]")
        .forEach((element) => {
          element.muted = nextDeafened;
          if (!nextDeafened) {
            element.volume = 1;
            void element.play().catch(() => setAudioPlaybackBlocked(true));
          }
        });
      if (!nextDeafened) {
        await room.startAudio();
      }
      setError(undefined);
    } catch {
      setError("Не удалось изменить режим заглушения");
      if (!nextDeafened) {
        setAudioPlaybackBlocked(true);
      }
    }
  }, [muted]);

  const toggleScreenShare = useCallback(
    async (quality: ScreenShareQuality) => {
      const room = roomRef.current;
      if (room === undefined) return;

      try {
        const preset = screenSharePreset(quality);
        await room.localParticipant.setScreenShareEnabled(!screenSharing, {
          audio: {
            autoGainControl: false,
            echoCancellation: false,
            noiseSuppression: false,
          },
          video: true,
          resolution: preset,
          contentHint: "motion",
          selfBrowserSurface: "exclude",
          surfaceSwitching: "include",
          systemAudio: "include",
          suppressLocalAudioPlayback: false,
        });
        const isSharing = room.localParticipant.isScreenShareEnabled;
        const hasAudio =
          room.localParticipant.getTrackPublication(
            Track.Source.ScreenShareAudio,
          ) !== undefined;
        setScreenSharing(isSharing);
        setScreenShareHasAudio(hasAudio);
        if (isSharing && !hasAudio) {
          setError(
            "Экран демонстрируется без звука. Остановите показ, запустите снова и включите «Поделиться аудио» в окне выбора.",
          );
          return;
        }
        setError(undefined);
      } catch (reason) {
        if (
          reason instanceof DOMException &&
          (reason.name === "NotAllowedError" || reason.name === "AbortError")
        ) {
          return;
        }
        setError(
          reason instanceof Error
            ? reason.message
            : "Не удалось начать демонстрацию экрана",
        );
      }
    },
    [screenSharing],
  );

  function screenSharePreset(quality: ScreenShareQuality) {
    switch (quality) {
      case "1080p60":
        return { width: 1920, height: 1080, frameRate: 60 };
      case "1080p30":
        return { width: 1920, height: 1080, frameRate: 30 };
      case "720p60":
        return { width: 1280, height: 720, frameRate: 60 };
      case "720p30":
        return { width: 1280, height: 720, frameRate: 30 };
      default:
        return { width: 1920, height: 1080, frameRate: 30 };
    }
  }

  const enableAudioPlayback = useCallback(async () => {
    const room = roomRef.current;
    if (room === undefined) return;
    try {
      await room.startAudio();
      const audioElements = document.querySelectorAll<HTMLMediaElement>(
        "[data-66msg-livekit-audio]",
      );
      await Promise.all(
        [...audioElements].map(async (element) => {
          element.volume = 1;
          await element.play();
        }),
      );
      setAudioPlaybackBlocked(false);
      setError(undefined);
    } catch {
      setError("Браузер не разрешил воспроизведение звука");
    }
  }, []);

  const setParticipantVoiceVolume = useCallback(
    (identity: string, volume: number) => {
      const normalized = normalizeVolume(volume);
      participantVoiceVolumesRef.current = {
        ...participantVoiceVolumesRef.current,
        [identity]: normalized,
      };
      setParticipantVoiceVolumes(participantVoiceVolumesRef.current);
      roomRef.current?.remoteParticipants
        .get(identity)
        ?.setVolume(normalized / 100, Track.Source.Microphone);
    },
    [],
  );

  const setParticipantShareVolume = useCallback(
    (identity: string, volume: number) => {
      const normalized = normalizeVolume(volume);
      participantShareVolumesRef.current = {
        ...participantShareVolumesRef.current,
        [identity]: normalized,
      };
      setParticipantShareVolumes(participantShareVolumesRef.current);
      roomRef.current?.remoteParticipants
        .get(identity)
        ?.setVolume(normalized / 100, Track.Source.ScreenShareAudio);
    },
    [],
  );

  return {
    state,
    muted,
    deafened,
    cameraEnabled,
    cameraFeeds,
    screenSharing,
    screenShareHasAudio,
    audioPlaybackBlocked,
    screenShares,
    participants: state === "connected" ? participants : observedParticipants,
    participantVoiceVolumes,
    participantShareVolumes,
    error,
    join,
    leave,
    toggleMute,
    toggleDeafen,
    toggleCamera,
    toggleScreenShare,
    enableAudioPlayback,
    setParticipantVoiceVolume,
    setParticipantShareVolume,
  };
}

function normalizeVolume(value: number): number {
  return Math.max(0, Math.min(200, Math.round(value)));
}

function isLiveKitParticipantsResponse(
  value: unknown,
): value is LiveKitParticipantsResponse {
  return (
    isRecord(value) &&
    Array.isArray(value.participants) &&
    value.participants.every(
      (participant) =>
        isRecord(participant) &&
        typeof participant.identity === "string" &&
        typeof participant.name === "string" &&
        typeof participant.muted === "boolean",
    )
  );
}

function isLiveKitTokenResponse(value: unknown): value is LiveKitTokenResponse {
  return (
    isRecord(value) &&
    typeof value.server_url === "string" &&
    typeof value.token === "string" &&
    typeof value.room_name === "string"
  );
}

function readErrorMessage(value: unknown): string {
  return isRecord(value) && typeof value.message === "string"
    ? value.message
    : "Не удалось подключиться к голосовому чату";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
