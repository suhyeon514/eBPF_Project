# Health 패키지

`health` 패키지는 에이전트의 순수 상태 관리 모듈입니다. 이 패키지는 `model` 패키지를 직접 참조하지 않으며, Kafka, collector, normalize 모듈과도 상호작용하지 않습니다. 대신 에이전트의 내부 상태를 추적하고 관리하는 데 중점을 둡니다.

## Registry

`Registry` 구조체는 `health` 패키지의 핵심입니다. 이 구조체는 에이전트의 내부 상태를 집계하며, 다음과 같은 정보를 포함합니다:
- 에이전트의 시작 시간 (`startedAt`)
- collector, normalize, output 모듈의 마지막 성공 작업 시간
- 처리된 이벤트의 총 개수
- 드롭된 이벤트의 개수

### 함수 설명

#### `NewRegistry`
새로운 `Registry` 인스턴스를 초기화하고 반환합니다. `startedAt` 필드를 현재 UTC 시간으로 설정합니다. 일반적으로 에이전트 초기화 단계에서 호출됩니다.

#### `MarkCollectorOK`
`lastCollectorOK` 필드를 현재 UTC 시간으로 업데이트합니다. collector가 이벤트를 성공적으로 처리할 때마다 호출됩니다.

#### `MarkNormalizeOK`
`lastNormalizeOK` 필드를 현재 UTC 시간으로 업데이트합니다. normalize 모듈이 이벤트를 성공적으로 처리할 때마다 호출됩니다.

#### `MarkOutputOK`
`lastOutputOK` 필드를 현재 UTC 시간으로 업데이트하고 `totalEvents` 카운터를 증가시킵니다. output 모듈이 이벤트를 성공적으로 처리할 때마다 호출됩니다.

#### `IncDrop`
`dropCount` 카운터를 증가시킵니다. 오류 또는 기타 문제로 인해 이벤트가 드롭될 때마다 호출됩니다.

#### `Snapshot`
현재 `Registry` 상태를 포함하는 `Snapshot` 구조체를 생성하고 반환합니다. 일반적으로 에이전트의 현재 상태를 보고하거나 로그를 생성하는 데 사용됩니다.