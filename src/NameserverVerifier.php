<?php

declare(strict_types = 1);

namespace ChiefTools\DNS\Resolver;

use Closure;
use InvalidArgumentException;
use ChiefTools\DNS\Resolver\Results\Record;
use ChiefTools\DNS\Resolver\Data\RootServers;
use ChiefTools\DNS\Resolver\Executors\RawRecord;
use ChiefTools\DNS\Resolver\Results\AnswerSource;
use ChiefTools\DNS\Resolver\Results\LookupResult;
use ChiefTools\DNS\Resolver\Executors\QueryResult;
use ChiefTools\DNS\Resolver\Results\NameserverAnswer;
use ChiefTools\DNS\Resolver\Exceptions\QueryException;
use ChiefTools\DNS\Resolver\Executors\DnsQueryExecutor;
use ChiefTools\DNS\Resolver\Enums\NameserverAnswerStatus;
use ChiefTools\DNS\Resolver\Results\AuthoritativeNameserver;
use ChiefTools\DNS\Resolver\Enums\NameserverVerificationStatus;
use ChiefTools\DNS\Resolver\Results\NameserverVerificationResult;
use ChiefTools\DNS\Resolver\Exceptions\ResolutionTimeoutException;
use ChiefTools\DNS\Resolver\Executors\DeadlineAwareDnsQueryExecutor;

final readonly class NameserverVerifier
{
    /** @param (\Closure(): int)|null $clock */
    public function __construct(
        private DnsQueryExecutor $executor,
        private ResolverConfig $config,
        private ?Closure $clock = null,
    ) {}

    /** @param (\Closure(\ChiefTools\DNS\Resolver\Results\NameserverAnswer): void)|null $onAnswer */
    public function verify(
        LookupResult $result,
        ?Closure $onAnswer,
        VerificationOptions $options,
    ): NameserverVerificationResult {
        if ($result->answerSources === null) {
            throw new InvalidArgumentException('Resolve with captureAnswerSources enabled before verifying nameservers.');
        }

        $deadline = new ResolutionDeadline($options->totalTimeout, $this->clock);
        $answers  = [];
        $statuses = [];
        $expired  = false;

        foreach ($result->answerSources as $source) {
            $baseline = new NameserverAnswer(
                sourceId: $source->id,
                nameserver: $source->selectedNameserver,
                address: $source->selectedAddress,
                responseCode: $source->responseCode,
                records: $source->records,
                status: NameserverAnswerStatus::BASELINE,
            );
            $this->emit($baseline, $answers, $onAnswer);

            $hasDifference  = false;
            $hasUnavailable = false;
            $peerCount      = 0;

            foreach ($source->nameservers as $nameserver) {
                if (strcasecmp(rtrim($nameserver->host, '.'), rtrim($source->selectedNameserver, '.')) === 0) {
                    continue;
                }

                $peerCount++;
                if ($expired) {
                    $answer = $this->unavailable($source, $nameserver, null, 'Verification deadline reached');
                } else {
                    try {
                        $deadline->throwIfExpired();
                        $answer = $this->queryPeer($source, $nameserver, $deadline, $options);
                    } catch (ResolutionTimeoutException) {
                        $expired = true;
                        $answer  = $this->unavailable($source, $nameserver, null, 'Verification deadline reached');
                    }
                }

                $hasDifference  = $hasDifference || $answer->status === NameserverAnswerStatus::DIFFERENT;
                $hasUnavailable = $hasUnavailable || $answer->status === NameserverAnswerStatus::UNAVAILABLE;
                $this->emit($answer, $answers, $onAnswer);
            }

            $statuses[$source->id] = match (true) {
                $peerCount === 0 => NameserverVerificationStatus::SINGLE,
                $hasDifference   => NameserverVerificationStatus::DIFFERENT,
                $hasUnavailable  => NameserverVerificationStatus::INCOMPLETE,
                default          => NameserverVerificationStatus::AGREE,
            };
        }

        return new NameserverVerificationResult($answers, $statuses);
    }

    private function queryPeer(
        AnswerSource $source,
        AuthoritativeNameserver $nameserver,
        ResolutionDeadline $deadline,
        VerificationOptions $options,
    ): NameserverAnswer {
        $addresses = $nameserver->addresses;
        if ($addresses === []) {
            $addresses = $this->resolveAddresses($nameserver->host, $deadline, $options);
        }

        $reason = 'No usable nameserver address';
        foreach (array_unique($addresses) as $address) {
            if (filter_var($address, FILTER_VALIDATE_IP) === false || ($options->allowAddress !== null && !($options->allowAddress)($address))) {
                continue;
            }

            try {
                $response = $this->query($source->queryName, $source->queryType, $address, $deadline);
            } catch (QueryException $exception) {
                $reason = $exception->getMessage();
                continue;
            }

            if (!in_array($response->responseCode, ['NOERROR', 'NXDOMAIN'], true)) {
                $reason = $response->responseCode;
                continue;
            }

            if ($response->answer === [] && array_any($response->authority, static fn (RawRecord $record): bool => $record->type === 'NS')) {
                $reason = 'Nameserver returned a referral';
                continue;
            }

            $records   = $this->answerRecords($source, $response);
            [$missing, $extra] = self::differences($source->records, $records);
            $different = $response->responseCode !== $source->responseCode || $missing !== [] || $extra !== [];

            return new NameserverAnswer(
                sourceId: $source->id,
                nameserver: $nameserver->host,
                address: $address,
                responseCode: $response->responseCode,
                records: $records,
                status: $different ? NameserverAnswerStatus::DIFFERENT : NameserverAnswerStatus::MATCH,
                missing: $missing,
                extra: $extra,
            );
        }

        return $this->unavailable($source, $nameserver, null, $reason);
    }

    /** @return list<string> */
    private function resolveAddresses(string $host, ResolutionDeadline $deadline, VerificationOptions $options): array
    {
        $session = new ResolutionSession(
            executor: $this->executor,
            config: $this->config,
            deadline: $this->executor instanceof DeadlineAwareDnsQueryExecutor ? $deadline : null,
            allowAddress: $options->allowAddress,
        );

        $result = $session->resolve(
            $host,
            $this->config->ipv6 ? ['A', 'AAAA'] : ['A'],
            RootServers::random(ipv6: $this->config->ipv6),
        );
        $deadline->throwIfExpired();

        if (!is_array($result)) {
            return [];
        }

        return array_values(array_map(
            static fn (RawRecord $record): string => $record->data,
            array_filter($result, static fn (RawRecord $record): bool => in_array($record->type, ['A', 'AAAA'], true)),
        ));
    }

    private function query(string $domain, string $type, string $address, ResolutionDeadline $deadline): QueryResult
    {
        $deadline->throwIfExpired();
        $response = $this->executor instanceof DeadlineAwareDnsQueryExecutor
            ? $this->executor->queryWithDeadline($domain, $type, $address, false, $deadline)
            : $this->executor->query($domain, $type, $address);
        $deadline->throwIfExpired();

        return $response;
    }

    /** @return list<\ChiefTools\DNS\Resolver\Results\Record> */
    private function answerRecords(AnswerSource $source, QueryResult $response): array
    {
        $owners = [strtolower(rtrim($source->queryName, '.')) => true];
        foreach ($source->records as $record) {
            $owners[strtolower(rtrim($record->name, '.'))] = true;
        }

        $records = [];
        foreach ($response->answer as $rawRecord) {
            if ($rawRecord->type === 'RRSIG' || $rawRecord->class !== 'IN' || !isset($owners[strtolower(rtrim($rawRecord->name, '.'))])) {
                continue;
            }

            $record = RecordFormatter::fromRaw($rawRecord, sourceId: $source->id);
            if ($record !== null) {
                $records[] = $record;
            }
        }

        return $records;
    }

    /**
     * @param list<\ChiefTools\DNS\Resolver\Results\Record> $baseline
     * @param list<\ChiefTools\DNS\Resolver\Results\Record> $peer
     *
     * @return array{list<\ChiefTools\DNS\Resolver\Results\Record>, list<\ChiefTools\DNS\Resolver\Results\Record>}
     */
    private static function differences(array $baseline, array $peer): array
    {
        $baselineSet = [];
        $peerSet     = [];
        foreach ($baseline as $record) {
            $baselineSet[self::recordKey($record)] = $record;
        }
        foreach ($peer as $record) {
            $peerSet[self::recordKey($record)] = $record;
        }

        return [array_values(array_diff_key($baselineSet, $peerSet)), array_values(array_diff_key($peerSet, $baselineSet))];
    }

    private static function recordKey(Record $record): string
    {
        $data = trim($record->rawData);
        $type = $record->type->value;

        if (in_array($type, ['A', 'AAAA'], true)) {
            $packed = inet_pton($data);
            $data   = $packed === false ? $data : bin2hex($packed);
        } elseif (in_array($type, ['CNAME', 'NS', 'PTR', 'DNAME'], true)) {
            $data = strtolower(rtrim($data, '.'));
        } elseif ($type === 'MX' || $type === 'SRV') {
            $parts = preg_split('/\s+/', $data);
            if ($parts !== false && $parts !== []) {
                $parts[count($parts) - 1] = strtolower(rtrim($parts[count($parts) - 1], '.'));
                $data                     = implode(' ', $parts);
            }
        } elseif (in_array($type, ['DS', 'CDS', 'SSHFP', 'TLSA', 'SMIMEA'], true)) {
            $data = strtolower(preg_replace('/\s+/', '', $data) ?? $data);
        }

        return strtolower(rtrim($record->name, '.')) . '|' . $type . '|' . $data;
    }

    private function unavailable(AnswerSource $source, AuthoritativeNameserver $nameserver, ?string $address, string $reason): NameserverAnswer
    {
        return new NameserverAnswer(
            sourceId: $source->id,
            nameserver: $nameserver->host,
            address: $address,
            responseCode: null,
            records: [],
            status: NameserverAnswerStatus::UNAVAILABLE,
            reason: $reason,
        );
    }

    /** @param list<\ChiefTools\DNS\Resolver\Results\NameserverAnswer> $answers @param (\Closure(\ChiefTools\DNS\Resolver\Results\NameserverAnswer): void)|null $onAnswer */
    private function emit(NameserverAnswer $answer, array &$answers, ?Closure $onAnswer): void
    {
        $answers[] = $answer;
        $onAnswer?->__invoke($answer);
    }
}
