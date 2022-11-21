#include "keeloqAnalyzer.h"
#include "keeloqAnalyzerSettings.h"
#include <AnalyzerChannelData.h>
#include <iostream>
using namespace std;

keeloqAnalyzer::keeloqAnalyzer() : Analyzer2(), mSettings(new keeloqAnalyzerSettings()), mSimulationInitilized(false) {
	SetAnalyzerSettings(mSettings.get());

	UseFrameV2();
}

keeloqAnalyzer::~keeloqAnalyzer() {
	KillThread();
}

void keeloqAnalyzer::SetupResults() {
	mResults.reset(new keeloqAnalyzerResults(this, mSettings.get()));
	SetAnalyzerResults(mResults.get());
	mResults->AddChannelBubblesWillAppearOn(mSettings->mInputChannel);
}

void keeloqAnalyzer::WorkerThread() {
	char result_str[128];

	mKeeloq = GetAnalyzerChannelData(mSettings->mInputChannel);

	mResults->AddResultString("Hello test\n");

	

	for (;; ) {
		bool bad_pckt = false;
		U64 data = 0;
		U64 data1 = 0;
		
		if (mKeeloq->GetBitState() == BIT_HIGH)
			mKeeloq->AdvanceToNextEdge();

		U64 width = mKeeloq->GetSampleOfNextEdge();
		mSampleW_preamb.clear();

		// looking a preambule

		//while (width < 20000) {
		//	mKeeloq->AdvanceToNextEdge();
		//	width = mKeeloq->GetSampleOfNextEdge();
		//}
		mKeeloq->AdvanceToNextEdge();
		mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Start, mSettings->mInputChannel);

		U64 starting_sample = mKeeloq->GetSampleNumber();

		mResults->AddResultString("preambule");
		for (U32 i = 0; i < 22; i++) { // through preambule
			width = abs(int(mKeeloq->GetSampleOfNextEdge() - mKeeloq->GetSampleNumber()));
			
			if (i > 1) { //detect right preambule
				U64 delta = abs(int(mSampleW_preamb[i-1] - width));
				if (delta > 200 && i < 10) {
					bad_pckt = true;
					break;
				}
			}

			mSampleW_preamb.push_back(width);
			mKeeloq->AdvanceToNextEdge();
		}
		
		if (!bad_pckt) {

			U64 middle_packet = (mSampleW_preamb[1] >> 1) * 3;

			mKeeloq->AdvanceToNextEdge();
			// looking a Encrypted Portion 32 bits
			
			mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::X, mSettings->mInputChannel);
			mResults->AddResultString("enc portion");

			for (U32 i = 0; i < 32; i++) {
				mKeeloq->AdvanceToNextEdge();
				mKeeloq->Advance(middle_packet); // set to middle
				if (mKeeloq->GetBitState() == BIT_HIGH) { // 0

					mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Square, mSettings->mInputChannel);
					mKeeloq->AdvanceToNextEdge();
				}
				else {
					// 1
					data |= 0x100000000;
					mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Square, mSettings->mInputChannel);
				}
				data >>= 1; //store as MSB LSB
			}
			
			// looking a Fixed Portion 34 bits
			mResults->AddResultString("fix portion");
			for (U32 i = 0; i < 32; i++) {
				mKeeloq->AdvanceToNextEdge();
				mKeeloq->Advance(middle_packet); // set to middle
				if (mKeeloq->GetBitState() == BIT_HIGH) { // 0
					mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Dot, mSettings->mInputChannel);
					mKeeloq->AdvanceToNextEdge();
				}
				else {
					// 1
					data1 |= 0x100000000;
					mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Dot, mSettings->mInputChannel);
				}
				data1 >>= 1; //store as MSB LSB
			}

			//add last 2 bits 
			for (U32 i = 0; i < 2; i++) {
				mKeeloq->AdvanceToNextEdge();
				mKeeloq->Advance(middle_packet); // set to middle
				if (mKeeloq->GetBitState() == BIT_HIGH) { // 0
					mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Dot, mSettings->mInputChannel);
					mKeeloq->AdvanceToNextEdge();
				}
				else {
					// 1
					data1 |= (U64)1<<(32+i);
					mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Dot, mSettings->mInputChannel);
				}
			}

			mKeeloq->Advance(middle_packet); // set to middle
			mResults->AddMarker(mKeeloq->GetSampleNumber(), AnalyzerResults::Stop, mSettings->mInputChannel);


			// we have a byte to save.
			Frame frame;
			frame.mData1 = data;
			frame.mData2 = data1;
			frame.mFlags = 0;
			frame.mStartingSampleInclusive = starting_sample;
			frame.mEndingSampleInclusive = mKeeloq->GetSampleNumber();

			mResults->AddFrame(frame);

			// New FrameV2 code.
			FrameV2 frame_v2;
			// you can add any number of key value pairs. Each will get it's own column in the data table.
			frame_v2.AddInteger("Fixed MSB LSB", frame.mData2);
			frame_v2.AddInteger("Encrupted MSB LSB", frame.mData1);

			// This actually saves your new FrameV2. In this example, we just copy the same start and end sample number from Frame V1 above.
			// The second parameter is the frame "type". Any string is allowed.
			mResults->AddFrameV2(frame_v2, "packet", starting_sample, frame.mEndingSampleInclusive);

			// You should already be calling this to make submitted frames available to the rest of the system. It's still required.

			mResults->CommitResults();
			ReportProgress(frame.mEndingSampleInclusive);
		}
	}
}

bool keeloqAnalyzer::NeedsRerun() {
	return false;
}

U32 keeloqAnalyzer::GenerateSimulationData(U64 minimum_sample_index, U32 device_sample_rate,
	SimulationChannelDescriptor** simulation_channels) {
	if (mSimulationInitilized == false) {
		mSimulationDataGenerator.Initialize(GetSimulationSampleRate(), mSettings.get());
		mSimulationInitilized = true;
	}

	return mSimulationDataGenerator.GenerateSimulationData(minimum_sample_index, device_sample_rate, simulation_channels);
}

U32 keeloqAnalyzer::GetMinimumSampleRateHz() {
	return mSettings->mBitRate * 4;
}

const char* keeloqAnalyzer::GetAnalyzerName() const {
	return "KEELOQ Code Hopping Encoder";
}

const char* GetAnalyzerName() {
	return "KEELOQ Code Hopping Encoder";
}

Analyzer* CreateAnalyzer() {
	return new keeloqAnalyzer();
}

void DestroyAnalyzer(Analyzer* analyzer) {
	delete analyzer;
}